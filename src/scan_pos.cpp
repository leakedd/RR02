// =============================================================================
// scan_pos.cpp — for each player object (rd5 list), scan ±0x2000 for valid
// world positions; print (offset, x, y, z). Decisive map for remote players.
// =============================================================================
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>

static task_t g_task;
static bool rmem(uint64_t a, void* b, size_t s) {
    vm_size_t got = 0;
    return vm_read_overwrite(g_task, (vm_address_t)a, s, (vm_address_t)b, &got) == KERN_SUCCESS && (size_t)got == s;
}
static uint64_t r64(uint64_t a) { uint64_t v = 0; rmem(a, &v, 8); return v; }
static float rf(uint64_t a) { float v = 0; rmem(a, &v, 4); return v; }
static bool in_world(float x, float y, float z) {
    if (!std::isfinite(x) || !std::isfinite(y) || !std::isfinite(z)) return false;
    return fabsf(x) < 4000 && fabsf(z) < 4000 && y > -100 && y < 1000;
}

// (addr, sid) from rd5
struct P { uint64_t a; uint64_t sid; };
static P PS[] = {
    {0x690a6c0e0, 76561198089239540}, {0x690a17740, 76561198110212185},
    {0x7af7d84c0, 76561198131295945}, {0x68531e2a0, 76561198683194576},
    {0x6887a7d00, 76561198755627002}, {0x68985f980, 76561198767306908},
    {0x68aaec980, 76561198984296471}, {0x690aaace0, 76561199055544702},
    {0x6869b3060, 76561199232739722},
};

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    pid_t pid = 0; int n = 0;
    pid_t pids[8192]; int np = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    for (int i = 0; i < np / (int)sizeof(pid_t); i++) {
        if (!pids[i]) continue; char path[PROC_PIDPATHINFO_MAXSIZE] = {};
        if (proc_pidpath(pids[i], path, sizeof(path)) > 0 && strstr(path, "RustClient")) { pid = pids[i]; break; }
    }
    if (!pid) { printf("[!] Rust not found\n"); return 1; }
    printf("[+] Rust PID=%d\n", pid);
    if (task_for_pid(mach_task_self(), pid, &g_task) != KERN_SUCCESS) { printf("[!] task_for_pid failed\n"); return 1; }

    for (auto& p : PS) {
        printf("== obj=0x%llx SID=%llu ==\n", (unsigned long long)p.a, (unsigned long long)p.sid);
        int hits = 0;
        // scan -0x2000 .. +0x3000 from object base, 4-byte aligned
        for (int64_t off = -0x2000; off < 0x3000; off += 4) {
            uint64_t ad = p.a + off;
            float x = rf(ad), y = rf(ad + 4), z = rf(ad + 8);
            if (!in_world(x, y, z)) continue;
            if (sqrtf(x * x + z * z) < 200.0f || y < 5.0f) continue;
            // require plausible ground-ish triple: reject obvious (0,0,k) patterns
            if (x == 0 && z == 0) continue;
            printf("    +0x%llx (%.1f, %.1f, %.1f)\n", (unsigned long long)off, x, y, z);
            hits++;
            if (hits >= 12) break;
        }
        if (!hits) printf("    (no world positions in range)\n");
    }
    return 0;
}
