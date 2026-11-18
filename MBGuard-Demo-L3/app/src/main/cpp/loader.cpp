// libmbguard_loader.so — L3 하드닝 로더(언패커 + JNI 브리지).
// 자기방어: ① 심볼 스트립 + visibility hidden(CMake) ② 문자열(키/논스/에셋명/경로/마커) XOR 난독화
//           ③ init_array 생성자에서 raw-syscall anti-debug(TracerPid) + anti-frida(maps 스캔) → 감지 시 키 오염(anti-dump).
// 클린 환경에선 정상 복호·로드. 디버거/Frida 존재 시 키가 틀어져 복호가 비-ELF로 실패한다(조용히).
// ★데모 레슨: 그래도 '결정적 경계'는 아니다 — init_array 방어선을 먼저 무력화(TracerPid/maps 후킹)하면 덤프가 가능하다.
#include <jni.h>
#include <android/asset_manager.h>
#include <android/asset_manager_jni.h>
#include <android/dlext.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include "chacha20.h"

// 하드닝: 로그 제거(no-op) — 태그·메시지 문자열이 바이너리에 남지 않게. 검증은 내부 모듈 DETECT 로그로.
#define LOGI(...) ((void)0)
#define LOGE(...) ((void)0)

// ── 난독화 패드 + 문자열(런타임 복호). 평문은 바이너리에 남지 않는다. ──
static const unsigned char OBF[8] = {0x5a,0xa5,0x3c,0xc3,0x17,0x71,0x8e,0xe8};
static const unsigned char KEY_OBF[32] = {0x17,0xe7,0x7b,0xb6,0x76,0x03,0xea,0xc5,0x16,0x96,0x11,0xa7,0x72,0x1c,0xe1,0xc5,0x31,0xc0,0x45,0xee,0x27,0x40,0xbc,0xdb,0x6e,0x90,0x0a,0xf4,0x2f,0x48,0xcf,0xaa};
static const unsigned char NONCE_OBF[12] = {0x37,0xc7,0x5b,0xee,0x79,0x1e,0xe0,0x8b,0x3f,0x88,0x0c,0xf2};
static const unsigned char ASSET_OBF[21] = {0x36,0xcc,0x5e,0xae,0x75,0x16,0xfb,0x89,0x28,0xc1,0x63,0xaf,0x61,0x43,0xa0,0x9b,0x35,0x8b,0x59,0xad,0x74};
static const unsigned char P_STATUS_OBF[17] = {0x75,0xd5,0x4e,0xac,0x74,0x5e,0xfd,0x8d,0x36,0xc3,0x13,0xb0,0x63,0x10,0xfa,0x9d,0x29};
static const unsigned char P_MAPS_OBF[15] = {0x75,0xd5,0x4e,0xac,0x74,0x5e,0xfd,0x8d,0x36,0xc3,0x13,0xae,0x76,0x01,0xfd};
static const unsigned char M_FRIDA_OBF[5] = {0x3c,0xd7,0x55,0xa7,0x76};
static const unsigned char M_GUM_OBF[6] = {0x3d,0xd0,0x51,0xee,0x7d,0x02};
static const unsigned char M_GADGET_OBF[6] = {0x3d,0xc4,0x58,0xa4,0x72,0x05};
static const unsigned char M_LINJ_OBF[9] = {0x36,0xcc,0x52,0xa9,0x72,0x12,0xfa,0x87,0x28};
static const unsigned char P_TASK_OBF[15] = {0x75,0xd5,0x4e,0xac,0x74,0x5e,0xfd,0x8d,0x36,0xc3,0x13,0xb7,0x76,0x02,0xe5};
static const unsigned char S_TRACER_OBF[10] = {0x0e,0xd7,0x5d,0xa0,0x72,0x03,0xde,0x81,0x3e,0x9f};
static const unsigned char S_LV2_OBF[17] = {0x36,0xcc,0x5e,0xae,0x75,0x16,0xfb,0x89,0x28,0xc1,0x63,0xaf,0x61,0x43,0xa0,0x9b,0x35};
static const unsigned char S_START_OBF[9] = {0x37,0xc7,0x5b,0x9c,0x64,0x05,0xef,0x9a,0x2e};
static const unsigned char S_STAT_OBF[12] = {0x37,0xc7,0x5b,0x9c,0x64,0x05,0xef,0x9c,0x2f,0xd6,0x59,0xb0};
static const unsigned char S_COINS_OBF[9] = {0x37,0xc7,0x5b,0x9c,0x74,0x1e,0xe7,0x86,0x29};
static const unsigned char S_COMM_OBF[5] = {0x75,0xc6,0x53,0xae,0x7a};
static const unsigned char S_TMP_OBF[8] = {0x74,0xc9,0x4a,0xf1,0x39,0x05,0xe3,0x98};

static void deobf(const unsigned char *e, int n, unsigned char *out) {
    for (int i = 0; i < n; i++) out[i] = (unsigned char)(e[i] ^ OBF[i & 7]);
    out[n] = 0;
}

// ── raw 시스템콜(svc #0) — libc 래퍼 미경유(후킹 포인트 축소) ──
#if defined(__aarch64__)
static long sys_openat(const char *path, int flags) {
    register long x8 asm("x8") = __NR_openat;
    register long x0 asm("x0") = -100; register long x1 asm("x1") = (long) path;
    register long x2 asm("x2") = flags; register long x3 asm("x3") = 0;
    asm volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3) : "memory", "cc");
    return x0;
}
static long sys_read(long fd, void *buf, unsigned long n) {
    register long x8 asm("x8") = __NR_read;
    register long x0 asm("x0") = fd; register long x1 asm("x1") = (long) buf; register long x2 asm("x2") = (long) n;
    asm volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory", "cc");
    return x0;
}
static long sys_close(long fd) {
    register long x8 asm("x8") = __NR_close; register long x0 asm("x0") = fd;
    asm volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory", "cc");
    return x0;
}
static long sys_getdents64(long fd, void *dirp, unsigned long count) {
    register long x8 asm("x8") = __NR_getdents64;
    register long x0 asm("x0") = fd; register long x1 asm("x1") = (long) dirp; register long x2 asm("x2") = (long) count;
    asm volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory", "cc");
    return x0;
}
#else
static long sys_openat(const char *p, int f) { return syscall(__NR_openat, AT_FDCWD, p, f, 0); }
static long sys_read(long fd, void *b, unsigned long n) { return syscall(__NR_read, fd, b, n); }
static long sys_close(long fd) { return syscall(__NR_close, fd); }
static long sys_getdents64(long fd, void *d, unsigned long c) { return syscall(__NR_getdents64, fd, d, c); }
#endif
struct ld64 { unsigned long d_ino; long d_off; unsigned short d_reclen; unsigned char d_type; char d_name[]; };

// 환경 오염비트(0=clean). init_array에서 설정 → nativeInit의 키에 섞인다.
static volatile unsigned char g_poison = 0;

// 디버거/ptrace 기반 계측(frida attach·gdb): TracerPid != 0
static int dbg_tracer() {
    unsigned char pb[20];
    deobf(P_STATUS_OBF, 17, pb);
    long fd = sys_openat((const char *) pb, O_RDONLY);
    if (fd < 0) return 0;
    char buf[2048];
    long n = sys_read(fd, buf, sizeof(buf) - 1);
    sys_close(fd);
    if (n <= 0) return 0;
    buf[n] = 0;
    unsigned char tr[12];
    deobf(S_TRACER_OBF, 10, tr);
    const char *p = strstr(buf, (char *) tr);
    return (p && atoi(p + 10) != 0) ? 1 : 0;
}

// frida 에이전트 로드 흔적: /proc/self/maps 에 frida/gum-js/gadget/linjector
static int dbg_frida_maps() {
    unsigned char pb[20];
    deobf(P_MAPS_OBF, 15, pb);
    long fd = sys_openat((const char *) pb, O_RDONLY);
    if (fd < 0) return 0;
    unsigned char m0[8], m1[8], m2[8], m3[12];
    deobf(M_FRIDA_OBF, 5, m0); deobf(M_GUM_OBF, 6, m1);
    deobf(M_GADGET_OBF, 6, m2); deobf(M_LINJ_OBF, 9, m3);
    char buf[8192];
    int hit = 0;
    long n;
    // 스트리밍 스캔(경계 겹침은 데모 범위에서 무시)
    while (!hit && (n = sys_read(fd, buf, sizeof(buf) - 1)) > 0) {
        buf[n] = 0;
        if (strstr(buf, (char *) m0) || strstr(buf, (char *) m1) ||
            strstr(buf, (char *) m2) || strstr(buf, (char *) m3)) hit = 1;
    }
    sys_close(fd);
    return hit;
}

// frida 스레드명(gum-js/pool-frida/linjector): /proc/self/task/*/comm — florida 익명주입도 스레드명은 노출.
static int dbg_frida_threads() {
    unsigned char tb[20];
    deobf(P_TASK_OBF, 15, tb);
    long dfd = sys_openat((const char *) tb, O_RDONLY | O_DIRECTORY);
    if (dfd < 0) return 0;
    unsigned char g1[8], g2[8], g3[12];
    deobf(M_GUM_OBF, 6, g1); deobf(M_FRIDA_OBF, 5, g2); deobf(M_LINJ_OBF, 9, g3);
    char dbuf[4096];
    int hit = 0;
    long nread;
    while (!hit && (nread = sys_getdents64(dfd, dbuf, sizeof(dbuf))) > 0) {
        long off = 0;
        while (off < nread) {
            struct ld64 *e = (struct ld64 *) (dbuf + off);
            const char *tid = e->d_name;
            if (tid[0] != '.') {
                char p[96]; int k = 0;
                for (int i = 0; tb[i]; i++) p[k++] = (char) tb[i];
                p[k++] = '/';
                for (int i = 0; tid[i]; i++) p[k++] = tid[i];
                unsigned char cm[8];
                deobf(S_COMM_OBF, 5, cm);
                for (int i = 0; cm[i]; i++) p[k++] = (char) cm[i];
                p[k] = 0;
                long cfd = sys_openat(p, O_RDONLY);
                if (cfd >= 0) {
                    char comm[64] = {0};
                    long n = sys_read(cfd, comm, sizeof(comm) - 1);
                    sys_close(cfd);
                    if (n > 0) {
                        comm[n] = 0;
                        if (strstr(comm, (char *) g1) || strstr(comm, (char *) g2) || strstr(comm, (char *) g3)) hit = 1;
                    }
                }
            }
            off += e->d_reclen;
        }
    }
    sys_close(dfd);
    return hit;
}

// ★init_array — 라이브러리 로드 시(JNI_OnLoad 이전) 실행되는 방어선.
__attribute__((constructor)) static void ctor_guard() {
    int hit = dbg_tracer() | dbg_frida_maps() | dbg_frida_threads();
    // clean=0, 감지 시 비-0(키 오염 상수). 단일 비교로 안 보이게 약간의 노이즈.
    g_poison = (unsigned char)((hit * 0x9e) | (hit << 3));
}

#define ENC_ASSET_LEN 21

typedef void        (*fn_start)(void);
typedef const int * (*fn_statuses)(int *);
typedef int         (*fn_coins)(void);
static fn_start    p_start    = 0;
static fn_statuses p_statuses = 0;
static fn_coins    p_coins    = 0;
static int         g_ready    = 0;

static int my_memfd(const char *name) {
#ifdef __NR_memfd_create
    return (int) syscall(__NR_memfd_create, name, 1u /* MFD_CLOEXEC */);
#else
    return -1;
#endif
}

static void *load_from_memory(uint8_t *elf, size_t len, const char *cache_dir) {
    void *handle = 0;
    int fd = my_memfd("m");
    if (fd >= 0) {
        if (write(fd, elf, len) == (ssize_t) len) {
            android_dlextinfo ext;
            memset(&ext, 0, sizeof(ext));
            ext.flags = ANDROID_DLEXT_USE_LIBRARY_FD;
            ext.library_fd = fd;
            unsigned char lv2[20];
            deobf(S_LV2_OBF, 17, lv2);
            handle = android_dlopen_ext((const char *) lv2, RTLD_NOW, &ext);
            if (!handle) LOGE("memfd dlopen failed: %s", dlerror());
        }
        close(fd);
    }
    if (handle) return handle;
    if (cache_dir && cache_dir[0]) {
        char path[1024];
        unsigned char tmp[12];
        deobf(S_TMP_OBF, 8, tmp);
        snprintf(path, sizeof(path), "%s/%s", cache_dir, (char *) tmp);
        int f = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (f >= 0) {
            ssize_t w = write(f, elf, len);
            close(f);
            if (w == (ssize_t) len) { handle = dlopen(path, RTLD_NOW); if (!handle) LOGE("fallback dlopen: %s", dlerror()); }
            unlink(path);
        }
    }
    return handle;
}

extern "C" JNIEXPORT void JNICALL
Java_com_mbbypass_mbguarddemo_Guard_nativeInit(JNIEnv *env, jobject thiz,
                                               jobject assetMgr, jstring cacheDir) {
    (void) thiz;
    if (g_ready) return;

    AAssetManager *am = AAssetManager_fromJava(env, assetMgr);
    if (!am) { LOGE("AssetManager null"); return; }
    unsigned char aname[ENC_ASSET_LEN + 1];
    deobf(ASSET_OBF, ENC_ASSET_LEN, aname);
    AAsset *a = AAssetManager_open(am, (const char *) aname, AASSET_MODE_BUFFER);
    if (!a) { LOGE("open asset failed"); return; }

    off_t len = AAsset_getLength(a);
    uint8_t *buf = (uint8_t *) malloc((size_t) len);
    if (!buf) { AAsset_close(a); return; }
    int rd = AAsset_read(a, buf, (size_t) len);
    AAsset_close(a);
    if (rd != (int) len) { LOGE("asset read short"); free(buf); return; }

    // 키/논스 난독 해제 후 환경 오염비트를 섞는다(분석 감지 시 키가 틀어짐).
    unsigned char key[33], nonce[13];
    deobf(KEY_OBF, 32, key);
    deobf(NONCE_OBF, 12, nonce);
    key[0] ^= g_poison;

    // ── 복호: 클린 환경이면 직후 buf = 평문 ELF (덤프 포인트) ──
    chacha20_xor(key, nonce, 0, buf, (size_t) len);
    memset(key, 0, sizeof(key));
    if (!(len > 4 && buf[0] == 0x7f && buf[1] == 'E' && buf[2] == 'L' && buf[3] == 'F')) {
        LOGE("decrypt produced non-ELF (analysis detected or key mismatch)");
        free(buf);
        return;
    }
    LOGI("inner module decrypted in memory (%ld bytes), ELF magic OK", (long) len);

    const char *cache = cacheDir ? env->GetStringUTFChars(cacheDir, 0) : 0;
    void *handle = load_from_memory(buf, (size_t) len, cache);
    if (cache) env->ReleaseStringUTFChars(cacheDir, cache);
    free(buf);
    if (!handle) { LOGE("inner module load failed"); return; }

    unsigned char s1[12], s2[16], s3[12];
    deobf(S_START_OBF, 9, s1);
    deobf(S_STAT_OBF, 12, s2);
    deobf(S_COINS_OBF, 9, s3);
    p_start    = (fn_start)    dlsym(handle, (char *) s1);
    p_statuses = (fn_statuses) dlsym(handle, (char *) s2);
    p_coins    = (fn_coins)    dlsym(handle, (char *) s3);
    if (!p_start || !p_statuses || !p_coins) { LOGE("inner exports missing"); return; }

    p_start();
    g_ready = 1;
    LOGI("L3 loader ready — inner watcher running (unpacked)");
}

extern "C" JNIEXPORT jintArray JNICALL
Java_com_mbbypass_mbguarddemo_Guard_getStatuses(JNIEnv *env, jobject thiz) {
    (void) thiz;
    int n = 12;
    const int *s = (g_ready && p_statuses) ? p_statuses(&n) : 0;
    jintArray arr = env->NewIntArray(n);
    if (s) env->SetIntArrayRegion(arr, 0, n, s);
    return arr;
}

extern "C" JNIEXPORT jint JNICALL
Java_com_mbbypass_mbguarddemo_Guard_getCoins(JNIEnv *env, jobject thiz) {
    (void) env;
    (void) thiz;
    return (g_ready && p_coins) ? p_coins() : 100;
}
