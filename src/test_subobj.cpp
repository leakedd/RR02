// =============================================================================
// test_subobj.cpp — for peer 0x690a6c0e0, collect heap ptrs in object, scan
// ±0x1000 around each for valid world positions.
// =============================================================================
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>
#include <set>
#include <algorithm>
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

const uint64_t OBJ = 0x690a6c0e0;

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
    printf("[+] PID=%d obj=0x%llx\n", pid, (unsigned long long)OBJ);

    std::vector<uint8_t> b(0x4000);
    if (!rmem(OBJ, b.data(), 0x4000)) { printf("[!] obj unreadable\n"); return 1; }
    std::set<uint64_t> ptrs;
    for (int o = 0; o + 8 <= 0x4000; o += 8) {
        uint64_t p; memcpy(&p, b.data() + o, 8);
        if (p > 0x100000000ULL && p < 0x7FFFFFFFFFFFULL) ptrs.insert(p);
    }
    printf("[+] %zu unique heap ptrs in object\n", ptrs.size());

    std::vector<uint8_t> sb(0x2000);
    int n = 0;
    for (uint64_t p : ptrs) {
        if (++n > 60) break;
        int found = 0;
        for (int64_t off = -0x1000; off < 0x1000 && found < 3; off += 4) {
            float x = rf(p + off), y = rf(p + off + 4), z = rf(p + off + 8);
            if (!in_world(x, y, z)) continue;
            if (sqrtf(x * x + z * z) < 200.0f || y < 5.0f) continue;
            if (x == 0 && z == 0) continue;
            printf("  ptr=0x%llx +0x%llx (%.1f, %.1f, %.1f)\n", (unsigned long long)p, (unsigned long long)off, x, y, z);
            found++;
        }
        if (found) printf("  --\n");
    }
    return 0;
}
