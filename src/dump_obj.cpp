// =============================================================================
// dump_obj.cpp — dump one player object: world-valid float triplets + native ptrs
// =============================================================================
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>
#include <string>

static task_t g_task;
static bool rmem(uint64_t a, void* b, size_t s) {
    vm_size_t got = 0;
    return vm_read_overwrite(g_task, (vm_address_t)a, s, (vm_address_t)b, &got) == KERN_SUCCESS && (size_t)got == s;
}
static uint64_t r64(uint64_t a) { uint64_t v = 0; rmem(a, &v, 8); return v; }
static float rf(uint64_t a) { float v = 0; rmem(a, &v, 4); return v; }

int main(int argc, char** argv) {
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
    uint64_t obj = argc > 1 ? strtoull(argv[1], NULL, 0) : 0x68aaec980ULL; // user obj
    printf("[*] Dumping obj 0x%llx\n", obj);
    printf("    vtable   = 0x%llx\n", r64(obj));
    printf("    +0x10    = 0x%llx (native ptr?)\n", r64(obj + 0x10));
    printf("    +0x18    = 0x%llx\n", r64(obj + 0x18));
    printf("    SID@0x1b0= %llu\n", r64(obj + 0x1b0));
    // world-valid float triplets
    std::vector<uint8_t> b(0x1000);
    if (!rmem(obj, b.data(), 0x1000)) { printf("[!] read fail\n"); return 1; }
    printf("\n[*] World-valid float triplets (|x|,|z|<4000, -100<y<1000):\n");
    for (int off = 0; off + 12 <= 0x1000; off += 4) {
        float x, y, z; memcpy(&x, b.data() + off, 4); memcpy(&y, b.data() + off + 4, 4); memcpy(&z, b.data() + off + 8, 4);
        if (!std::isfinite(x) || !std::isfinite(y) || !std::isfinite(z)) continue;
        if (fabsf(x) < 4000 && fabsf(z) < 4000 && y > -100 && y < 1000) {
            printf("    +0x%03x: (%.2f, %.2f, %.2f)\n", off, x, y, z);
        }
    }
    // native ptrs
    printf("\n[*] Pointer-like qwords in obj:\n");
    for (int off = 0; off + 8 <= 0x1000; off += 8) {
        uint64_t v; memcpy(&v, b.data() + off, 8);
        if (v > 0x10000 && v < 0x7FFFFFFFFFFFULL) {
            // check readable
            uint64_t t = 0;
            if (rmem(v, &t, 8)) {
                printf("    +0x%03x -> 0x%llx [first=0x%llx]\n", off, v, t);
            }
        }
    }
    return 0;
}
