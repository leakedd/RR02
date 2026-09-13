// =============================================================================
// test_stability.cpp — re-read candidate GameObject positions twice (3s apart)
// for peer 0x690a6c0e0; flag moving vs static. Also read local +0x1168.
// =============================================================================
#include <cstdio>
#include <cstdint>
#include <cmath>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>

static task_t g_task;
static bool rmem(uint64_t a, void* b, size_t s) {
    vm_size_t got = 0;
    return vm_read_overwrite(g_task, (vm_address_t)a, s, (vm_address_t)b, &got) == KERN_SUCCESS && (size_t)got == s;
}
static float rf(uint64_t a) { float v = 0; rmem(a, &v, 4); return v; }

struct C { const char* tag; uint64_t addr; };
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

    C cands[] = {
        {"peer0 GO+0x400 (0x78c9929b0)", 0x78c9929b0 + 0x358},
        {"peer0 GO+0x740 (0x78c98d330)", 0x78c98d330 + 0x358},
        {"peer0 GO+0xb40 (0x6ed062f60)", 0x6ed062f60 + 0x358},
        {"peer0 GO+0xe40 (0x78c985f70)", 0x78c985f70 + 0x358},
        {"user  +0x1168 (direct)",        0x68aaec980 + 0x1168},
        {"user  +0x10e0 (direct)",        0x68aaec980 + 0x10e0},
    };
    int n = sizeof(cands) / sizeof(cands[0]);
    float x0[8], y0[8], z0[8];
    for (int i = 0; i < n; i++) {
        x0[i] = rf(cands[i].addr); y0[i] = rf(cands[i].addr + 4); z0[i] = rf(cands[i].addr + 8);
    }
    sleep(3);
    for (int i = 0; i < n; i++) {
        float x1 = rf(cands[i].addr), y1 = rf(cands[i].addr + 4), z1 = rf(cands[i].addr + 8);
        float d = sqrtf((x1 - x0[i]) * (x1 - x0[i]) + (y1 - y0[i]) * (y1 - y0[i]) + (z1 - z0[i]) * (z1 - z0[i]));
        printf("%-32s t0=(%8.1f,%6.1f,%8.1f) t1=(%8.1f,%6.1f,%8.1f) delta=%.2fm\n",
               cands[i].tag, x0[i], y0[i], z0[i], x1, y1, z1, d);
    }
    return 0;
}
