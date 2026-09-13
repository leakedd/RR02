// =============================================================================
// test_transform.cpp — find (Transform klass, ptr) pairs in each player object,
// read world pos via Unity TransformData ([t+0x28]+0x90). Decisive for remotes.
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

const uint64_t K_TRANSFORM = 0x12f8a0b70; // Il2CppClass Transform (seen)
const uint64_t K_GAMEOBJECT = 0x12f88d670;

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
        int nT = 0, nG = 0;
        for (int o = 0; o + 0x18 <= 0x4000; o += 8) {
            uint64_t k; memcpy(&k, b.data() + o, 8);
            uint64_t v; memcpy(&v, b.data() + o + 0x10, 8);
            if (k == K_TRANSFORM) {
                nT++;
                if (nT <= 4) {
                    // Unity 6: [t+0x28] = TransformData*, [td+0x90] = root pos
                    float x = rf(v + 0x28 + 0x90), y = rf(v + 0x28 + 0x94), z = rf(v + 0x28 + 0x98);
                    float x2 = rf(v + 0x90), y2 = rf(v + 0x94), z2 = rf(v + 0x98);
                    printf("    T@+0x%x ptr=0x%llx td=0x%llx pos_td=(%.1f,%.1f,%.1f)%s pos_direct=(%.1f,%.1f,%.1f)%s\n",
                           o, (unsigned long long)v, (unsigned long long)r64(v + 0x28),
                           x, y, z, in_world(x, y, z) ? " WORLD" : "",
                           x2, y2, z2, in_world(x2, y2, z2) ? " WORLD" : "");
                }
            } else if (k == K_GAMEOBJECT) {
                nG++;
            }
        }
        printf("    (%d Transform refs, %d GameObject refs)\n", nT, nG);
    }
    return 0;
}
