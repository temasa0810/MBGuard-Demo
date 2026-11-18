// MBGuard-Demo-L3 내부 탐지 모듈(libmbguard_lv2.so) — L2 하드닝 로직과 동일(문자열 XOR·심볼스트립·raw 안티디버그).
// 차이: JNI를 제거하고 C-ABI export(mbg_start/mbg_statuses/mbg_coins)만 노출한다. JNI는 로더(loader.cpp)가 소유한다.
// 이 .so는 암호화되어 assets로만 동봉되고, 로드 순간 메모리에서만 복호된다(L3 패킹). 탐지 12종을 0.5초마다 재검사.
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
#define MBG_EXPORT extern "C" __attribute__((visibility("default")))

#define CHECKING 0
#define CLEAR    1
#define DETECTED 2
#define NCHECK   12

static volatile int g_status[NCHECK] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

// 문자열 XOR 암호화 (하드닝 A). key 8바이트 순환. 평문은 주석에만.
static const unsigned char XKEY[8] = {0x37,0x91,0xc4,0x5a,0xe3,0x1f,0x88,0x6d};
static char *ux(const unsigned char *e, int n, char *out) {
    for (int i = 0; i < n; i++) out[i] = (char)(e[i] ^ XKEY[i & 7]);
    out[n] = 0;
    return out;
}
struct Enc { const unsigned char *e; int n; };

static const unsigned char e_frida[] = {0x51,0xe3,0xad,0x3e,0x82}; // "frida" (5)
static const unsigned char e_gum[] = {0x50,0xe4,0xa9}; // "gum" (3)
static const unsigned char e_gmain[] = {0x50,0xfc,0xa5,0x33,0x8d}; // "gmain" (5)
static const unsigned char e_poolfrida[] = {0x47,0xfe,0xab,0x36,0xce,0x79,0xfa,0x04,0x53,0xf0}; // "pool-frida" (10)
static const unsigned char e_linjector[] = {0x5b,0xf8,0xaa,0x30,0x86,0x7c,0xfc,0x02,0x45}; // "linjector" (9)
static const unsigned char e_gumjs[] = {0x50,0xe4,0xa9,0x77,0x89,0x6c}; // "gum-js" (6)
static const unsigned char e_gadget[] = {0x50,0xf0,0xa0,0x3d,0x86,0x6b}; // "gadget" (6)
static const unsigned char e_su_prod_bin[] = {0x18,0xe1,0xb6,0x35,0x87,0x6a,0xeb,0x19,0x18,0xf3,0xad,0x34,0xcc,0x6c,0xfd}; // "/product/bin/su" (15)
static const unsigned char e_su_prod_xbin[] = {0x18,0xe1,0xb6,0x35,0x87,0x6a,0xeb,0x19,0x18,0xe9,0xa6,0x33,0x8d,0x30,0xfb,0x18}; // "/product/xbin/su" (16)
static const unsigned char e_su_dbgr[] = {0x18,0xf5,0xa1,0x38,0x96,0x78,0xd7,0x1f,0x56,0xfc,0xa0,0x33,0x90,0x74,0xa7,0x1e,0x42}; // "/debug_ramdisk/su" (17)
static const unsigned char e_su_sys_bin[] = {0x18,0xe2,0xbd,0x29,0x97,0x7a,0xe5,0x42,0x55,0xf8,0xaa,0x75,0x90,0x6a}; // "/system/bin/su" (14)
static const unsigned char e_su_sys_xbin[] = {0x18,0xe2,0xbd,0x29,0x97,0x7a,0xe5,0x42,0x4f,0xf3,0xad,0x34,0xcc,0x6c,0xfd}; // "/system/xbin/su" (15)
static const unsigned char e_su_sysext[] = {0x18,0xe2,0xbd,0x29,0x97,0x7a,0xe5,0x32,0x52,0xe9,0xb0,0x75,0x81,0x76,0xe6,0x42,0x44,0xe4}; // "/system_ext/bin/su" (18)
static const unsigned char e_su_vendor[] = {0x18,0xe7,0xa1,0x34,0x87,0x70,0xfa,0x42,0x55,0xf8,0xaa,0x75,0x90,0x6a}; // "/vendor/bin/su" (14)
static const unsigned char e_su_sbin[] = {0x18,0xe2,0xa6,0x33,0x8d,0x30,0xfb,0x18}; // "/sbin/su" (8)
static const unsigned char e_su_apex[] = {0x18,0xf0,0xb4,0x3f,0x9b,0x30,0xeb,0x02,0x5a,0xbf,0xa5,0x34,0x87,0x6d,0xe7,0x04,0x53,0xbf,0xb6,0x2f,0x8d,0x6b,0xe1,0x00,0x52,0xbe,0xa6,0x33,0x8d,0x30,0xfb,0x18}; // "/apex/com.android.runtime/bin/su" (32)
static const unsigned char e_mg_dbgr[] = {0x18,0xf5,0xa1,0x38,0x96,0x78,0xd7,0x1f,0x56,0xfc,0xa0,0x33,0x90,0x74,0xa7,0x00,0x56,0xf6,0xad,0x29,0x88}; // "/debug_ramdisk/magisk" (21)
static const unsigned char e_mg_dbgr_dot[] = {0x18,0xf5,0xa1,0x38,0x96,0x78,0xd7,0x1f,0x56,0xfc,0xa0,0x33,0x90,0x74,0xa7,0x43,0x5a,0xf0,0xa3,0x33,0x90,0x74}; // "/debug_ramdisk/.magisk" (22)
static const unsigned char e_mg_dbgr32[] = {0x18,0xf5,0xa1,0x38,0x96,0x78,0xd7,0x1f,0x56,0xfc,0xa0,0x33,0x90,0x74,0xa7,0x00,0x56,0xf6,0xad,0x29,0x88,0x2c,0xba}; // "/debug_ramdisk/magisk32" (23)
static const unsigned char e_mg_dbgr64[] = {0x18,0xf5,0xa1,0x38,0x96,0x78,0xd7,0x1f,0x56,0xfc,0xa0,0x33,0x90,0x74,0xa7,0x00,0x56,0xf6,0xad,0x29,0x88,0x29,0xbc}; // "/debug_ramdisk/magisk64" (23)
static const unsigned char e_mg_sbin[] = {0x18,0xe2,0xa6,0x33,0x8d,0x30,0xa6,0x00,0x56,0xf6,0xad,0x29,0x88}; // "/sbin/.magisk" (13)
static const unsigned char e_mg_dev[] = {0x18,0xf5,0xa1,0x2c,0xcc,0x31,0xe5,0x0c,0x50,0xf8,0xb7,0x31}; // "/dev/.magisk" (12)
static const unsigned char e_mg_dataadb[] = {0x18,0xf5,0xa5,0x2e,0x82,0x30,0xe9,0x09,0x55,0xbe,0xa9,0x3b,0x84,0x76,0xfb,0x06}; // "/data/adb/magisk" (16)
static const unsigned char e_prop_tags[] = {0x45,0xfe,0xea,0x38,0x96,0x76,0xe4,0x09,0x19,0xe5,0xa5,0x3d,0x90}; // "ro.build.tags" (13)
static const unsigned char e_testkeys[] = {0x43,0xf4,0xb7,0x2e,0xce,0x74,0xed,0x14,0x44}; // "test-keys" (9)
static const unsigned char e_mnt_magisk[] = {0x5a,0xf0,0xa3,0x33,0x90,0x74}; // "magisk" (6)
static const unsigned char e_mnt_dbgr[] = {0x18,0xf5,0xa1,0x38,0x96,0x78,0xd7,0x1f,0x56,0xfc,0xa0,0x33,0x90,0x74}; // "/debug_ramdisk" (14)
static const unsigned char e_mnt_ksu[] = {0x7c,0xc2,0x91}; // "KSU" (3)
static const unsigned char e_mnt_worker[] = {0x40,0xfe,0xb6,0x31,0x86,0x6d}; // "worker" (6)
static const unsigned char e_sym_access[] = {0x56,0xf2,0xa7,0x3f,0x90,0x6c}; // "access" (6)
static const unsigned char e_sym_fgetschk[] = {0x68,0xce,0xa2,0x3d,0x86,0x6b,0xfb,0x32,0x54,0xf9,0xaf}; // "__fgets_chk" (11)
static const unsigned char e_sym_fopen[] = {0x51,0xfe,0xb4,0x3f,0x8d}; // "fopen" (5)
static const unsigned char e_libself[] = {0x5b,0xf8,0xa6,0x37,0x81,0x78,0xfd,0x0c,0x45,0xf5,0x9b,0x36,0x95,0x2d,0xa6,0x1e,0x58}; // "libmbguard_lv2.so" (17)
static const unsigned char e_dotso[] = {0x19,0xe2,0xab}; // ".so" (3)
static const unsigned char e_p_maps[] = {0x18,0xe1,0xb6,0x35,0x80,0x30,0xfb,0x08,0x5b,0xf7,0xeb,0x37,0x82,0x6f,0xfb}; // "/proc/self/maps" (15)
static const unsigned char e_p_task[] = {0x18,0xe1,0xb6,0x35,0x80,0x30,0xfb,0x08,0x5b,0xf7,0xeb,0x2e,0x82,0x6c,0xe3}; // "/proc/self/task" (15)
static const unsigned char e_p_status[] = {0x18,0xe1,0xb6,0x35,0x80,0x30,0xfb,0x08,0x5b,0xf7,0xeb,0x29,0x97,0x7e,0xfc,0x18,0x44}; // "/proc/self/status" (17)
static const unsigned char e_p_mounts[] = {0x18,0xe1,0xb6,0x35,0x80,0x30,0xfb,0x08,0x5b,0xf7,0xeb,0x37,0x8c,0x6a,0xe6,0x19,0x44}; // "/proc/self/mounts" (17)

static int looks_like_frida(const char *comm) {
    static const Enc bad[] = {{e_frida,5},{e_gum,3},{e_gmain,5},{e_poolfrida,10},{e_linjector,9}};
    char b[24];
    for (unsigned i = 0; i < sizeof(bad)/sizeof(bad[0]); i++)
        if (strstr(comm, ux(bad[i].e, bad[i].n, b))) return 1;
    return 0;
}

// ── [0] 스레드명 스캔 ──
static int check_threadname() {
    char tb[20];
    DIR *d = opendir(ux(e_p_task, 15, tb));
    if (!d) return CLEAR;
    int hit = 0;
    struct dirent *e;
    while ((e = readdir(d)) != 0) {
        if (e->d_name[0] == '.') continue;
        char path[256], tb2[20];
        snprintf(path, sizeof(path), "%s/%s/comm", ux(e_p_task, 15, tb2), e->d_name);
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

// ── [1] 메모리맵 스캔 ──
static int check_maps() {
    char pb[20];
    FILE *f = fopen(ux(e_p_maps, 15, pb), "r");
    if (!f) return CLEAR;
    char line[512];
    int hit = 0;
    char a[12], b[12], c[16], d[12];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, ux(e_frida, 5, a)) || strstr(line, ux(e_gumjs, 6, b)) ||
            strstr(line, ux(e_linjector, 9, c)) || strstr(line, ux(e_gadget, 6, d))) { hit = 1; break; }
    }
    fclose(f);
    return hit ? DETECTED : CLEAR;
}

// ── [2] ptrace 디버거 (파일 API) ──
static int check_ptrace() {
    char pb[20];
    FILE *f = fopen(ux(e_p_status, 17, pb), "r");
    if (!f) return CLEAR;
    char line[256];
    int tracer = 0;
    while (fgets(line, sizeof(line), f)) {
        if (strncmp(line, "TracerPid:", 10) == 0) { tracer = atoi(line + 10); break; }
    }
    fclose(f);
    return tracer != 0 ? DETECTED : CLEAR;
}

// ── [3] 트램폴린/인라인훅 ──
static void *g_acc_addr = 0;
static unsigned char g_acc_base[16];
static int g_acc_ok = 0;
static int check_trampoline() {
    if (!g_acc_ok || !g_acc_addr) return CLEAR;
    return memcmp(g_acc_addr, g_acc_base, 16) != 0 ? DETECTED : CLEAR;
}

// ── 인라인 svc #0 시스템콜 ──
#if defined(__aarch64__)
static long sys_openat(const char *path, int flags) {
    register long x8 asm("x8") = __NR_openat;
    register long x0 asm("x0") = -100;
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
    char pb[20];
    long fd = sys_openat(ux(e_p_maps, 15, pb), O_RDONLY);
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

static int is_in_legit_exec(unsigned long addr) {
    char so[6];
    const char *dot_so = ux(e_dotso, 3, so);
    const char *line = g_maps;
    while (line && *line) {
        unsigned long a1 = 0, a2 = 0, off; char perms[8] = {0}, dev[16] = {0}, path[300] = {0};
        long inode = 0;
        int nf = sscanf(line, "%lx-%lx %7s %lx %15s %ld %299s", &a1, &a2, perms, &off, dev, &inode, path);
        if (nf >= 7 && perms[2] == 'x' && path[0] == '/' && strstr(path, dot_so) &&
            addr >= a1 && addr < a2)
            return 1;
        const char *nl = strchr(line, '\n');
        if (!nl) break;
        line = nl + 1;
    }
    return 0;
}

// ── [4] 실행권한 익명메모리 ──
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

// ── [5] GOT/import 무결성 ──
static int g_got_hooked = 0;
static int got_phdr_cb(struct dl_phdr_info *info, size_t sz, void *data) {
    (void) sz; (void) data;
    char lb[20];
    if (!info->dlpi_name || !strstr(info->dlpi_name, ux(e_libself, 17, lb))) return 0;
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
    char wa[8], wf[14], wo[8];
    const char *watch[] = {ux(e_sym_access, 6, wa), ux(e_sym_fgetschk, 11, wf), ux(e_sym_fopen, 5, wo), 0};
    size_t n = pltrelsz / sizeof(ElfW(Rela));
    for (size_t i = 0; i < n; i++) {
        unsigned long si = ELF64_R_SYM(jmprel[i].r_info);
        const char *name = strtab + symtab[si].st_name;
        int w = 0;
        for (int k = 0; watch[k]; k++) if (strcmp(name, watch[k]) == 0) { w = 1; break; }
        if (!w) continue;
        void *target = *(void **) (base + jmprel[i].r_offset);
        if (!target || !is_in_legit_exec((unsigned long) target)) { g_got_hooked = 1; return 1; }
    }
    return 1;
}
static int check_got() {
    g_got_hooked = 0;
    if (read_maps_raw() <= 0) return CLEAR;
    dl_iterate_phdr(got_phdr_cb, 0);
    return g_got_hooked ? DETECTED : CLEAR;
}

// ── [6] 코드 무결성 (.text 자가해시) ──
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
    char lb[20];
    if (!info->dlpi_name || !strstr(info->dlpi_name, ux(e_libself, 17, lb))) return 0;
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

// ── [7] 안티디버그 (raw syscall TracerPid) ──
static int check_antidebug_raw() {
    char pb[20];
    long fd = sys_openat(ux(e_p_status, 17, pb), O_RDONLY);
    if (fd < 0) return CLEAR;
    char buf[4096];
    long n = sys_read(fd, buf, sizeof(buf) - 1);
    sys_close(fd);
    if (n <= 0) return CLEAR;
    buf[n] = 0;
    const char *p = strstr(buf, "TracerPid:");
    if (!p) return CLEAR;
    int tracer = atoi(p + 10);
    return tracer != 0 ? DETECTED : CLEAR;
}

// ── [8] su 바이너리 경로 ──
static int check_su() {
    static const Enc P[] = {
        {e_su_prod_bin,15},{e_su_prod_xbin,16},{e_su_dbgr,17},{e_su_sys_bin,14},
        {e_su_sys_xbin,15},{e_su_sysext,18},{e_su_vendor,14},{e_su_sbin,8},{e_su_apex,32}};
    char b[40];
    for (unsigned i = 0; i < sizeof(P)/sizeof(P[0]); i++)
        if (access(ux(P[i].e, P[i].n, b), F_OK) == 0) return DETECTED;
    return CLEAR;
}

// ── [9] Magisk 흔적 ──
static int check_magisk() {
    static const Enc P[] = {
        {e_mg_dbgr,21},{e_mg_dbgr_dot,22},{e_mg_dbgr32,23},{e_mg_dbgr64,23},
        {e_mg_sbin,13},{e_mg_dev,12},{e_mg_dataadb,16}};
    char b[40];
    for (unsigned i = 0; i < sizeof(P)/sizeof(P[0]); i++)
        if (access(ux(P[i].e, P[i].n, b), F_OK) == 0) return DETECTED;
    return CLEAR;
}

// ── [10] test-keys 빌드태그 ──
static int check_testkeys() {
    char nb[16], tb[12];
    char v[PROP_VALUE_MAX] = {0};
    __system_property_get(ux(e_prop_tags, 13, nb), v);
    return strstr(v, ux(e_testkeys, 9, tb)) ? DETECTED : CLEAR;
}

// ── [11] mount 정보 ──
static int check_mount() {
    char pb[20];
    FILE *f = fopen(ux(e_p_mounts, 17, pb), "r");
    if (!f) return CLEAR;
    char line[1024];
    int hit = 0;
    char a[8], b[16], c[6], d[8];
    while (fgets(line, sizeof(line), f)) {
        if (strstr(line, ux(e_mnt_magisk, 6, a)) || strstr(line, ux(e_mnt_dbgr, 14, b)) ||
            strstr(line, ux(e_mnt_ksu, 3, c)) || strstr(line, ux(e_mnt_worker, 6, d))) { hit = 1; break; }
    }
    fclose(f);
    return hit ? DETECTED : CLEAR;
}

static const unsigned char e_names[NCHECK][14] = {
    {0x43,0xf9,0xb6,0x3f,0x82,0x7b,0xe6,0x0c,0x5a,0xf4}, // "threadname" (10)
    {0x5a,0xf0,0xb4,0x29},                               // "maps" (4)
    {0x47,0xe5,0xb6,0x3b,0x80,0x7a},                     // "ptrace" (6)
    {0x43,0xe3,0xa5,0x37,0x93,0x70,0xe4,0x04,0x59,0xf4}, // "trampoline" (10)
    {0x45,0xe6,0xbc},                                    // "rwx" (3)
    {0x70,0xde,0x90},                                    // "GOT" (3)
    {0x5e,0xff,0xb0,0x3f,0x84,0x6d,0xe1,0x19,0x4e},      // "integrity" (9)
    {0x56,0xff,0xb0,0x33,0x87,0x7a,0xea,0x18,0x50,0xce,0xb6,0x3b,0x94}, // "antidebug_raw" (13)
    {0x44,0xe4},                                         // "su" (2)
    {0x5a,0xf0,0xa3,0x33,0x90,0x74},                     // "magisk" (6)
    {0x43,0xf4,0xb7,0x2e,0x88,0x7a,0xf1,0x1e},           // "testkeys" (8)
    {0x5a,0xfe,0xb1,0x34,0x97},                          // "mount" (5)
};
static const int e_names_n[NCHECK] = {10, 4, 6, 10, 3, 3, 9, 13, 2, 6, 8, 5};
static int g_prev[NCHECK] = {0};

static void *detect_thread(void *arg) {
    (void) arg;
    for (;;) {
        g_status[0]  = check_threadname();
        g_status[1]  = check_maps();
        g_status[2]  = check_ptrace();
        g_status[3]  = check_trampoline();
        g_status[4]  = check_rwx();
        g_status[5]  = check_got();
        g_status[6]  = check_integrity();
        g_status[7]  = check_antidebug_raw();
        g_status[8]  = check_su();
        g_status[9]  = check_magisk();
        g_status[10] = check_testkeys();
        g_status[11] = check_mount();
        for (int i = 0; i < NCHECK; i++) {
            if (g_status[i] == DETECTED && g_prev[i] != DETECTED) {
                char nb[16];
                LOGW("DETECT [%d] %s", i, ux(e_names[i], e_names_n[i], nb));
            }
            g_prev[i] = g_status[i];
        }
        usleep(500 * 1000);
    }
    return 0;
}

static int g_coins = 100;
static int g_started = 0;

// ── 로더가 호출하는 C-ABI export (JNI는 로더가 소유) ──
MBG_EXPORT void mbg_start(void) {
    if (g_started) return;
    g_started = 1;
    LOGI("MBGuard-L3 inner module started (unpacked in memory)");
    char sb[8];
    g_acc_addr = dlsym(RTLD_DEFAULT, ux(e_sym_access, 6, sb));
    if (g_acc_addr) { memcpy(g_acc_base, g_acc_addr, 16); g_acc_ok = 1; }
    dl_iterate_phdr(text_phdr_cb, 0);
    if (g_text_addr && g_text_len) g_text_hash = fnv1a((const unsigned char *) g_text_addr, g_text_len);
    pthread_t t;
    pthread_create(&t, 0, detect_thread, 0);
}

MBG_EXPORT const int *mbg_statuses(int *n) {
    if (n) *n = NCHECK;
    return (const int *) g_status;
}

MBG_EXPORT int mbg_coins(void) {
    return g_coins;
}
