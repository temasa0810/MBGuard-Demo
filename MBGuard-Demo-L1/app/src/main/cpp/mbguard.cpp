// MBGuard-Demo 네이티브 보호 모듈 — Frida/후킹·루팅 탐지 6종을 0.5초마다 재검사하고 상태만 기록(종료 없음). 교육용 의도적 취약 데모.
#include <jni.h>
#include <dirent.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <fcntl.h>
#include <dlfcn.h>
#include <link.h>
#include <elf.h>
#include <sys/syscall.h>
#include <sys/system_properties.h>
#include <android/log.h>

#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, "MBGuard", __VA_ARGS__)
#define LOGW(...) __android_log_print(ANDROID_LOG_WARN, "MBGuard", __VA_ARGS__)

// 상태 코드 (Kotlin 현황판과 공유)
#define CHECKING 0
#define CLEAR    1   // 통과(미탐지)
#define DETECTED 2   // 탐지됨
#define NCHECK   11

// index 순서: 0~6 = Frida/후킹 탐지, 7~10 = 루팅 탐지(네이티브). Java 패키지/권한 탐지는 Kotlin에서 별도.
static volatile int g_status[NCHECK] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

// 탐지 대상 스레드명 흔적 (Frida가 심는 전형적 이름)
static const char *kBad[] = {"frida", "gum", "gmain", "pool-frida", "linjector", 0};
static int looks_like_frida(const char *comm) {
    for (int i = 0; kBad[i]; i++)
        if (strstr(comm, kBad[i])) return 1;
    return 0;
}

// ── [0] 스레드명 스캔 (/proc/self/task/*/comm) ─ 우회: comm rename 후킹 ──────
static int check_threadname() {
    DIR *d = opendir("/proc/self/task");
    if (!d) return CLEAR;
    int hit = 0;
    struct dirent *e;
    while ((e = readdir(d)) != 0) {
        if (e->d_name[0] == '.') continue;
        char path[256];
        snprintf(path, sizeof(path), "/proc/self/task/%s/comm", e->d_name);
        FILE *f = fopen(path, "r");
        if (!f) continue;
        char comm[64] = {0};
        if (fgets(comm, sizeof(comm), f) && looks_like_frida(comm)) hit = 1;
        fclose(f);
        if (hit) break;
    }
    closedir(d);
    return hit ? DETECTED : CLEAR;
}

// ── [1] 메모리맵 스캔 (/proc/self/maps) ─ 우회: open/read 또는 strstr 후킹 ──
static int check_maps() {
    FILE *f = fopen("/proc/self/maps", "r");
    if (!f) return CLEAR;
    char line[512];
    int hit = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "frida") || strstr(line, "gum-js") ||
            strstr(line, "linjector") || strstr(line, "gadget")) { hit = 1; break; }
    }
    fclose(f);
    return hit ? DETECTED : CLEAR;
}

// ── [2] ptrace 디버거 ─ TracerPid!=0 (frida warm-attach=ptrace) ──────────────
// 우회: /proc/self/status open·read 후킹으로 TracerPid 0 스푸핑.
static int check_ptrace() {
    FILE *f = fopen("/proc/self/status", "r");
    if (!f) return CLEAR;
    char line[256];
    int tracer = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) { tracer = atoi(line + 10); break; }
    }
    fclose(f);
    return tracer != 0 ? DETECTED : CLEAR;
}

// ── [3] 트램폴린/인라인훅 ─ 함수 prologue가 패치됐는지 baseline 대조 ─────────
// 로드시 access()의 첫 16바이트를 스냅샷→매 루프 비교. Interceptor.attach/인라인훅이
// prologue를 트램폴린으로 덮으면 바이트가 달라져 탐지. 우회=트램폴린 안 쓰는 훅(테이블/methodPointer).
static void *g_acc_addr = 0;
static unsigned char g_acc_base[16];
static int g_acc_ok = 0;
static int check_trampoline() {
    if (!g_acc_ok || !g_acc_addr) return CLEAR;
    return memcmp(g_acc_addr, g_acc_base, 16) != 0 ? DETECTED : CLEAR;
}

// ── 인라인 svc #0 시스템콜 (★라운드5: libc syscall() 래퍼도 안 거침) ──
// 라운드4의 raw 리더는 libc `syscall()` 래퍼를 거쳐, 공격자가 그 GOT를 리다이렉트하면 재우회 가능했음.
// 인라인 asm `svc #0`은 래퍼 없이 커널로 직접 진입 → 후킹할 libc 함수가 아예 없음.
// (한계: svc 명령이 든 우리 .text를 인라인 패치하면 뚫림 → 라운드6 코드무결성이 그 패치를 포착)
#if defined(__aarch64__)
static long sys_openat(const char *path, int flags) {
    register long x8 asm("x8") = __NR_openat;
    register long x0 asm("x0") = -100;              // AT_FDCWD
    register long x1 asm("x1") = (long) path;
    register long x2 asm("x2") = flags;
    register long x3 asm("x3") = 0;
    asm volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2), "r"(x3) : "memory", "cc");
    return x0;
}
static long sys_read(long fd, void *buf, unsigned long n) {
    register long x8 asm("x8") = __NR_read;
    register long x0 asm("x0") = fd;
    register long x1 asm("x1") = (long) buf;
    register long x2 asm("x2") = (long) n;
    asm volatile("svc #0" : "+r"(x0) : "r"(x8), "r"(x1), "r"(x2) : "memory", "cc");
    return x0;
}
static long sys_close(long fd) {
    register long x8 asm("x8") = __NR_close;
    register long x0 asm("x0") = fd;
    asm volatile("svc #0" : "+r"(x0) : "r"(x8) : "memory", "cc");
    return x0;
}
#else
static long sys_openat(const char *p, int f) { return syscall(__NR_openat, AT_FDCWD, p, f, 0); }
static long sys_read(long fd, void *b, unsigned long n) { return syscall(__NR_read, fd, b, n); }
static long sys_close(long fd) { return syscall(__NR_close, fd); }
#endif

static char g_maps[256 * 1024];
static int read_maps_raw() {
    long fd = sys_openat("/proc/self/maps", O_RDONLY);
    if (fd < 0) return 0;
    int total = 0;
    long n;
    while (total < (int) sizeof(g_maps) - 1 &&
           (n = sys_read(fd, g_maps + total, sizeof(g_maps) - 1 - total)) > 0)
        total += (int) n;
    sys_close(fd);
    g_maps[total] = 0;
    return total;
}

// 주소가 "파일 백업 실행영역(.so)" 안에 있는지 — g_maps를 비파괴 파싱(dladdr 불필요=후킹 무관)
static int is_in_legit_exec(unsigned long addr) {
    const char *line = g_maps;
    while (line && *line) {
        unsigned long a1 = 0, a2 = 0, off; char perms[8] = {0}, dev[16] = {0}, path[300] = {0};
        long inode = 0;
        int nf = sscanf(line, "%lx-%lx %7s %lx %15s %ld %299s", &a1, &a2, perms, &off, dev, &inode, path);
        if (nf >= 7 && perms[2] == 'x' && path[0] == '/' && strstr(path, ".so") &&
            addr >= a1 && addr < a2)
            return 1;
        const char *nl = strchr(line, '\n');
        if (!nl) break;
        line = nl + 1;
    }
    return 0;
}

// ── [4] 실행권한 익명메모리 (RASP II) ─ ★raw 시스템콜로 maps 읽어 익명 rwx 카운트 ──
static int check_rwx() {
    if (read_maps_raw() <= 0) return CLEAR;
    int cnt = 0;
    const char *line = g_maps;
    while (line && *line) {
        unsigned long a1, a2, off; char perms[8] = {0}, dev[16] = {0}, path[300] = {0};
        long inode = 0;
        int nf = sscanf(line, "%lx-%lx %7s %lx %15s %ld %299s", &a1, &a2, perms, &off, dev, &inode, path);
        if (perms[0]=='r' && perms[1]=='w' && perms[2]=='x' && (nf < 7 || inode == 0)) cnt++;
        const char *nl = strchr(line, '\n');
        if (!nl) break;
        line = nl + 1;
    }
    return cnt > 0 ? DETECTED : CLEAR;
}

// ── [5] GOT/import 무결성 ─ import 포인터가 정상 라이브러리 밖(익명메모리)을 가리키는지 ──
// 트램폴린(코드 패치)을 피한 GOT 리다이렉트 훅도, import 슬롯이 익명 콜백을 가리키는 흔적을 남김.
// dl_iterate_phdr로 libmbguard의 .rela.plt 파싱→watch 심볼의 GOT 값을 ★raw maps 범위로 검증(dladdr 미사용).
// 어제 bypass가 dladdr을 GOT 리다이렉트해 뚫었으므로, 판정을 후킹 가능한 dladdr이 아닌 maps 자가파싱으로 대체.
static int g_got_hooked = 0;
static int got_phdr_cb(struct dl_phdr_info *info, size_t sz, void *data) {
    (void) sz; (void) data;
    if (!info->dlpi_name || !strstr(info->dlpi_name, "libmbguard.so")) return 0;
    ElfW(Addr) base = info->dlpi_addr;
    const ElfW(Dyn) *dyn = 0;
    for (int i = 0; i < info->dlpi_phnum; i++)
        if (info->dlpi_phdr[i].p_type == PT_DYNAMIC) {
            dyn = (const ElfW(Dyn) *) (base + info->dlpi_phdr[i].p_vaddr); break;
        }
    if (!dyn) return 1;
    const ElfW(Sym) *symtab = 0; const char *strtab = 0;
    const ElfW(Rela) *jmprel = 0; size_t pltrelsz = 0;
    for (; dyn->d_tag != DT_NULL; dyn++) {
        if (dyn->d_tag == DT_SYMTAB)        symtab  = (const ElfW(Sym) *) (base + dyn->d_un.d_ptr);
        else if (dyn->d_tag == DT_STRTAB)   strtab  = (const char *)       (base + dyn->d_un.d_ptr);
        else if (dyn->d_tag == DT_JMPREL)   jmprel  = (const ElfW(Rela) *) (base + dyn->d_un.d_ptr);
        else if (dyn->d_tag == DT_PLTRELSZ) pltrelsz = dyn->d_un.d_val;
    }
    if (!symtab || !strtab || !jmprel || !pltrelsz) return 1;
    static const char *watch[] = {"access", "__fgets_chk", "fopen", 0};
    size_t n = pltrelsz / sizeof(ElfW(Rela));
    for (size_t i = 0; i < n; i++) {
        unsigned long si = ELF64_R_SYM(jmprel[i].r_info);
        const char *name = strtab + symtab[si].st_name;
        int w = 0;
        for (int k = 0; watch[k]; k++) if (strcmp(name, watch[k]) == 0) { w = 1; break; }
        if (!w) continue;
        void *target = *(void **) (base + jmprel[i].r_offset);
        // ★강화: dladdr(후킹당함) 대신 raw maps 범위로 자가검증 — 정상 .so 실행영역 밖이면 훅
        if (!target || !is_in_legit_exec((unsigned long) target)) { g_got_hooked = 1; return 1; }
    }
    return 1;  // 우리 모듈 처리 완료
}
static int check_got() {
    g_got_hooked = 0;
    if (read_maps_raw() <= 0) return CLEAR;   // raw 시스템콜로 maps 스냅샷(is_in_legit_exec가 사용)
    dl_iterate_phdr(got_phdr_cb, 0);
    return g_got_hooked ? DETECTED : CLEAR;
}

// ── [6] 코드 무결성 (.text 자가해시) ─ 라운드6: 우리 .text 코드가 패치됐는지 ──
// svc를 인라인화해도(라5) 그 svc 명령이 든 .text를 공격자가 인라인 패치하거나, 체크 함수째 NOP하면 뚫림.
// 로드시 libmbguard의 실행 세그먼트(PF_X PT_LOAD) 해시를 baseline → 매 루프 재해시. 코드 변조시 달라져 탐지.
// (GOT는 쓰기 세그먼트라 비포함 → GOT 리다이렉트는 여기 안 걸리고 [5]가 담당. 여긴 순수 코드 패치 탐지)
// (한계: 이 자가검증 코드 역시 인프로세스라 또 패치 가능=무한회귀. 진짜 경계=HW/서버 증명)
static void *g_text_addr = 0;
static unsigned long g_text_len = 0;
static unsigned long g_text_hash = 0;
static unsigned long fnv1a(const unsigned char *p, unsigned long n) {
    unsigned long h = 1469598103934665603UL;
    for (unsigned long i = 0; i < n; i++) { h ^= p[i]; h *= 1099511628211UL; }
    return h;
}
static int text_phdr_cb(struct dl_phdr_info *info, size_t sz, void *data) {
    (void) sz; (void) data;
    if (!info->dlpi_name || !strstr(info->dlpi_name, "libmbguard.so")) return 0;
    for (int i = 0; i < info->dlpi_phnum; i++) {
        const ElfW(Phdr) *p = &info->dlpi_phdr[i];
        if (p->p_type == PT_LOAD && (p->p_flags & PF_X)) {
            g_text_addr = (void *) (info->dlpi_addr + p->p_vaddr);
            g_text_len = p->p_memsz;
            return 1;
        }
    }
    return 1;
}
static int check_integrity() {
    if (!g_text_addr || g_text_len == 0) return CLEAR;
    unsigned long h = fnv1a((const unsigned char *) g_text_addr, g_text_len);
    return h != g_text_hash ? DETECTED : CLEAR;
}

// ── [7] su 바이너리 경로 ─ 우회: access/stat 후킹(ENOENT 스푸핑) ────────────
// 주의: 최신 Magisk su는 /product/bin·/debug_ramdisk에 있음(구식 /system/bin/su 아님).
static int check_su() {
    static const char *paths[] = {
        "/product/bin/su", "/product/xbin/su", "/debug_ramdisk/su",
        "/system/bin/su", "/system/xbin/su", "/system_ext/bin/su",
        "/vendor/bin/su", "/sbin/su", "/apex/com.android.runtime/bin/su", 0};
    for (int i = 0; paths[i]; i++)
        if (access(paths[i], F_OK) == 0) return DETECTED;
    return CLEAR;
}

// ── [8] Magisk 흔적 ─ 우회: access/open 경로 스푸핑 ────────────────────────
// 주의: /data/adb/*는 0700 root라 앱 uid가 접근 불가(무용). 앱이 볼 수 있는 흔적만 검사.
static int check_magisk() {
    static const char *paths[] = {
        "/debug_ramdisk/magisk", "/debug_ramdisk/.magisk",
        "/debug_ramdisk/magisk32", "/debug_ramdisk/magisk64",
        "/sbin/.magisk", "/dev/.magisk", "/data/adb/magisk", 0};
    for (int i = 0; paths[i]; i++)
        if (access(paths[i], F_OK) == 0) return DETECTED;
    return CLEAR;
}

// ── [9] test-keys 빌드태그 ─ 우회: __system_property_get 후킹(값 스푸핑) ────
static int check_testkeys() {
    char v[PROP_VALUE_MAX] = {0};
    __system_property_get("ro.build.tags", v);
    return strstr(v, "test-keys") ? DETECTED : CLEAR;
}

// ── [10] mount 정보 ─ 우회: /proc/self/mounts open·read 후킹 또는 Shamiko ──
// Magisk는 /debug_ramdisk·/product/bin 등에 "tmpfs magisk" 마운트를 남김. Zygisk/Shamiko가 꺼지면
// 앱 네임스페이스에서 안 지워져 그대로 보임(파일 숨겨도 마운트는 잡힘).
static int check_mount() {
    FILE *f = fopen("/proc/self/mounts", "r");
    if (!f) return CLEAR;
    char line[1024];
    int hit = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, "magisk") || strstr(line, "/debug_ramdisk") ||
            strstr(line, "KSU") || strstr(line, "worker")) { hit = 1; break; }
    }
    fclose(f);
    return hit ? DETECTED : CLEAR;
}

// 체크 이름 (logcat 증거 로깅용 — getStatuses(UI)와 독립 채널)
static const char *kCheckName[NCHECK] = {
    "threadname", "maps", "ptrace", "trampoline", "rwx", "GOT", "integrity",
    "su", "magisk", "testkeys", "mount"
};
static int g_prev[NCHECK] = {0};

// ── 주기적 재검사 루프 (종료 없음 — 상태만 갱신) ──────────────────────────
static void *detect_thread(void *arg) {
    (void) arg;
    for (;;) {
        g_status[0] = check_threadname();
        g_status[1] = check_maps();
        g_status[2] = check_ptrace();
        g_status[3] = check_trampoline();
        g_status[4] = check_rwx();
        g_status[5] = check_got();
        g_status[6] = check_integrity();
        g_status[7] = check_su();
        g_status[8] = check_magisk();
        g_status[9] = check_testkeys();
        g_status[10] = check_mount();
        // ★탐지 증거 로깅 — 통과→탐지 전이 시점에 logcat에 남김(UI 보고 위조와 무관한 side-channel).
        //   verdict-level 우회(getStatuses 위조)로 현황판을 전부 통과로 꾸며도, 이 로그는 실제 탐지를 증언.
        for (int i = 0; i < NCHECK; i++) {
            if (g_status[i] == DETECTED && g_prev[i] != DETECTED)
                LOGW("DETECT [%d] %s", i, kCheckName[i]);
            g_prev[i] = g_status[i];
        }
        usleep(500 * 1000);  // 0.5s
    }
    return 0;
}

extern "C" JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved) {
    (void) vm;
    (void) reserved;
    LOGI("MBGuard loaded — detection watcher (non-terminating)");
    // 트램폴린 탐지용 baseline — access()의 깨끗한 prologue 16바이트 스냅샷
    g_acc_addr = dlsym(RTLD_DEFAULT, "access");
    if (g_acc_addr) { memcpy(g_acc_base, g_acc_addr, 16); g_acc_ok = 1; }
    // 코드 무결성 baseline — libmbguard 실행 세그먼트(.text) 해시 스냅샷
    dl_iterate_phdr(text_phdr_cb, 0);
    if (g_text_addr && g_text_len) g_text_hash = fnv1a((const unsigned char *) g_text_addr, g_text_len);
    pthread_t t;
    pthread_create(&t, 0, detect_thread, 0);
    return JNI_VERSION_1_6;
}

// 현황판이 0.5초마다 폴링하는 상태 배열
extern "C" JNIEXPORT jintArray JNICALL
Java_com_mbbypass_mbguarddemo_Guard_getStatuses(JNIEnv *env, jobject thiz) {
    (void) thiz;
    jint tmp[NCHECK];
    for (int i = 0; i < NCHECK; i++) tmp[i] = g_status[i];
    jintArray arr = env->NewIntArray(NCHECK);
    env->SetIntArrayRegion(arr, 0, NCHECK, tmp);
    return arr;
}

// ── 조작 대상 — 네이티브 코인 값 (hook가 반환값을 바꿀 함수) ──────────────
static int g_coins = 100;

extern "C" JNIEXPORT jint JNICALL
Java_com_mbbypass_mbguarddemo_Guard_getCoins(JNIEnv *env, jobject thiz) {
    (void) env;
    (void) thiz;
    return g_coins;
}
