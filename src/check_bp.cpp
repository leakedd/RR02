// =============================================================================
// check_bp.cpp — test UC offsets against live player objects (build 24614784)
//   SID@0x718 (BasePlayer.userID), playerModel@0x340 -> position@0x2F8
// =============================================================================
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
static bool is_sid(uint64_t v) { return v >= 76561197960265728ULL && v < 76561202255233023ULL; }

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
    if (!g_task) { printf("[!] not found\n"); return 1; }

    const uint64_t objs[] = {
        0x785e84c00ULL, 0x7859f1760ULL, 0x785ac99e0ULL, 0x782386160ULL, 0x785e85b20ULL,
        0x782382b40ULL, 0x7757e10a0ULL, 0x68531e2a0ULL, 0x6887a7d00ULL, 0x68985f980ULL,
        0x774cda800ULL, 0x68aaec980ULL, 0x785aba160ULL, 0x7724fa800ULL, 0x6869b3060ULL,
        0x774a616e0ULL, 0x774d944c0ULL, 0x7720c0c40ULL, 0x691b8e080ULL, 0x77c52fa60ULL,
    };
    printf("  obj          SID@0x1b0        SID@0x718       pm@0x340     pos(pm+0x2F8)\n");
    for (size_t i = 0; i < sizeof(objs)/8; i++) {
        uint64_t o = objs[i];
        uint64_t sid_1b0 = r64(o + 0x1b0);
        uint64_t sid_718 = r64(o + 0x718);
        uint64_t pm = r64(o + 0x340);
        float x = 0, y = 0, z = 0;
        uint64_t pm_valid = 0;
        if (pm > 0x10000 && pm < 0x7FFFFFFFFFFFULL) {
            if (rmem(pm + 0x2F8, &x, 4) && rmem(pm + 0x2F8 + 4, &y, 4) && rmem(pm + 0x2F8 + 8, &z, 4)) pm_valid = 1;
        }
        printf("%c 0x%llx  %s  %s  0x%llx  (%.1f, %.1f, %.1f)%s\n",
            (is_sid(sid_1b0) || is_sid(sid_718)) ? '>' : ' ',
            o,
            is_sid(sid_1b0) ? "SID  " : "-----",
            is_sid(sid_718) ? "SID  " : "-----",
            pm, x, y, z,
            pm_valid && fabsf(x) < 4000 && fabsf(z) < 4000 ? "  <-- world?" : "");
    }
    return 0;
}
