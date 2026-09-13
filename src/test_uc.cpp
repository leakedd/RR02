// test_uc.cpp — verify UC thread offsets (build 24614784) against live local player on macOS
// Thread (damianskater): userID=0x718 playerModel=0x340 PlayerModel.position=0x2F8
// playerEyes=0x7a0 PlayerInventory=0x4b0 metabolism=0x3a0 baseMovement=0x520
// modelState=0x2d0 _displayName=0x390 playerFlags=0x6d0
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>

static task_t g_task;
static bool rmem(uint64_t a, void* b, size_t s) {
    vm_size_t got = 0;
    return vm_read_overwrite(g_task, (vm_address_t)a, s, (vm_address_t)b, &got) == KERN_SUCCESS && (size_t)got == s;
}
static uint64_t r64(uint64_t a) { uint64_t v = 0; rmem(a, &v, 8); return v; }
static float rf(uint64_t a) { float v = 0; rmem(a, &v, 4); return v; }
static uint32_t r32(uint64_t a) { uint32_t v = 0; rmem(a, &v, 4); return v; }
static bool is_sid(uint64_t v) { return v >= 76561197960265728ULL && v < 76561202255233023ULL; }
static bool valid_ptr(uint64_t p) { return p > 0x10000 && p < 0x7FFFFFFFFFFFULL; }

static void dump_pos(const char* tag, uint64_t a) {
    float x = rf(a), y = rf(a + 4), z = rf(a + 8);
    bool ok = std::isfinite(x) && std::isfinite(y) && std::isfinite(z) && fabsf(x) < 4000 && fabsf(z) < 4000 && y > -100 && y < 1000;
    printf("    %-30s = (%.2f, %.2f, %.2f)%s\n", tag, x, y, z, ok ? "  <== WORLD" : "");
}

static void dump_unity_string(const char* tag, uint64_t p) {
    if (!valid_ptr(p)) { printf("    %-30s = (null)\n", tag); return; }
    uint32_t len = r32(p + 0x10);
    if (len > 64) { printf("    %-30s = len=%u (suspicious)\n", tag, len); return; }
    char buf[128] = {};
    for (uint32_t i = 0; i < len && i < 63; i++) {
        uint16_t c = 0; rmem(p + 0x14 + i * 2, &c, 2);
        buf[i] = (c >= 32 && c < 127) ? (char)c : '?';
    }
    printf("    %-30s = \"%s\" (len=%u)\n", tag, buf, len);
}

int main() {
    pid_t pids[8192]; int n = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    for (int i = 0; i < n / (int)sizeof(pid_t); i++) {
        if (!pids[i]) continue; char path[PROC_PIDPATHINFO_MAXSIZE] = {};
        if (proc_pidpath(pids[i], path, sizeof(path)) > 0 && strstr(path, "RustClient")) {
            task_for_pid(mach_task_self(), pids[i], &g_task);
            printf("[+] Rust PID=%d\n", pids[i]);
            break;
        }
    }
    if (!g_task) { printf("task_for_pid FAILED\n"); return 1; }

    // Known stable local object (from prior sessions)
    uint64_t obj = 0x68aaec980ULL;
    printf("=== Local object 0x%llx ===\n", (unsigned long long)obj);
    printf("    [obj+0x00] vtable          = 0x%llx\n", (unsigned long long)r64(obj));
    printf("    [obj+0x718] userID         = %llu (sid? %s)\n", r64(obj + 0x718), is_sid(r64(obj + 0x718)) ? "YES" : "no");
    uint64_t pm = r64(obj + 0x340);
    printf("    [obj+0x340] playerModel    = 0x%llx\n", (unsigned long long)pm);
    if (valid_ptr(pm)) {
        printf("    [pm+0x00] vtable           = 0x%llx\n", (unsigned long long)r64(pm));
        dump_pos("[pm+0x2F8] position (UC)", pm + 0x2F8);
        dump_pos("[pm+0x31C] newVelocity", pm + 0x31C);
        dump_unity_string("[pm+0x98] rootBone name?", r64(pm + 0x98));
    }
    dump_pos("[obj+0x1168] direct pos (ours)", obj + 0x1168);
    uint64_t eyes = r64(obj + 0x7a0);
    printf("    [obj+0x7a0] playerEyes     = 0x%llx\n", (unsigned long long)eyes);
    if (valid_ptr(eyes)) {
        printf("      [eyes+0x10] flag byte    = 0x%x\n", r32(eyes + 0x10));
        printf("      [eyes+0x18] hval         = 0x%llx\n", (unsigned long long)r64(eyes + 0x18));
    }
    uint64_t inv = r64(obj + 0x4b0);
    printf("    [obj+0x4b0] inventory      = 0x%llx\n", (unsigned long long)inv);
    uint64_t meta = r64(obj + 0x3a0);
    printf("    [obj+0x3a0] metabolism     = 0x%llx\n", (unsigned long long)meta);
    uint64_t mv = r64(obj + 0x520);
    printf("    [obj+0x520] baseMovement   = 0x%llx\n", (unsigned long long)mv);
    if (valid_ptr(mv)) {
        dump_pos("[mv+0x130] velocity", mv + 0x130);
        float ga = rf(mv + 0x110);
        printf("    [mv+0x110] groundAngleNew  = %.4f\n", ga);
    }
    printf("    [obj+0x6d0] playerFlags    = 0x%x\n", r32(obj + 0x6d0));
    printf("    [obj+0x2d0] modelState     = 0x%llx\n", (unsigned long long)r64(obj + 0x2d0));
    dump_unity_string("[obj+0x390] displayName", r64(obj + 0x390));
    dump_unity_string("[obj+0x4e8] UserIDString", r64(obj + 0x4e8));
    // control: 0x1168 group
    dump_pos("[obj+0x10e0] alt pos", obj + 0x10e0);
    return 0;
}
