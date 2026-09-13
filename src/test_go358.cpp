// =============================================================================
// test_go358.cpp — for each player, for each (GameObject klass, ptr) pair,
// read [ptr+0x358] as world pos. Verify against known local pos (-147.3,31,1517.6)
// =============================================================================
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>
#include <set>
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

const uint64_t K_GO = 0x12f88d670; // GameObject klass

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
    pid_t pid = 0;
    pid_t pids[8192]; int np = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    for (int i = 0; i < np / (int)sizeof(pid_t); i++) {
        if (!pids[i]) continue; char path[PROC_PIDPATHINFO_MAXSIZE] = {};
        if (proc_pidpath(pids[i], path, sizeof(path)) > 0 && strstr(path, "RustClient")) { pid = pids[i]; break; }
    }
    if (!pid) { printf("[!] Rust not found\n"); return 1; }
    if (task_for_pid(mach_task_self(), pid, &g_task) != KERN_SUCCESS) { printf("[!] task_for_pid failed\n"); return 1; }
    printf("[+] PID=%d\n", pid);

    std::vector<uint8_t> b(0x4000);
    for (auto& p : PS) {
        printf("== obj=0x%llx SID=%llu ==\n", (unsigned long long)p.a, (unsigned long long)p.sid);
        if (!rmem(p.a, b.data(), 0x4000)) { printf("    (unreadable)\n"); continue; }
        std::set<uint64_t> seen;
        int n = 0;
        for (int o = 0; o + 0x18 <= 0x4000; o += 8) {
            uint64_t k, v;
            memcpy(&k, b.data() + o, 8);
            memcpy(&v, b.data() + o + 0x10, 8);
            if (k != K_GO || !seen.insert(v).second) continue;
            float x = rf(v + 0x358), y = rf(v + 0x358 + 4), z = rf(v + 0x358 + 8);
            float x2 = rf(v + 0x90), y2 = rf(v + 0x90 + 4), z2 = rf(v + 0x90 + 8);
            printf("    GO@+0x%x ptr=0x%llx [p+0x358]=(%.1f,%.1f,%.1f)%s  [p+0x90]=(%.1f,%.1f,%.1f)%s\n",
                   o, (unsigned long long)v, x, y, z, in_world(x, y, z) && fabsf(x) + fabsf(z) > 100 ? " WORLD" : "",
                   x2, y2, z2, in_world(x2, y2, z2) && fabsf(x2) + fabsf(z2) > 100 ? " WORLD" : "");
            if (++n >= 6) break;
        }
        if (!n) printf("    (no GameObject pairs)\n");
    }
    return 0;
}
