// =============================================================================
// dump_hex.cpp — hex dump region of an object to understand element layout
// =============================================================================
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <vector>

static task_t g_task;
static bool rmem(uint64_t a, void* b, size_t s) {
    vm_size_t got = 0;
    return vm_read_overwrite(g_task, (vm_address_t)a, s, (vm_address_t)b, &got) == KERN_SUCCESS && (size_t)got == s;
}

int main(int argc, char** argv) {
    pid_t pids[8192]; int n = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    for (int i = 0; i < n / (int)sizeof(pid_t); i++) {
        if (!pids[i]) continue; char path[PROC_PIDPATHINFO_MAXSIZE] = {};
        if (proc_pidpath(pids[i], path, sizeof(path)) > 0 && strstr(path, "RustClient")) {
            task_for_pid(mach_task_self(), pids[i], &g_task);
            break;
        }
    }
    uint64_t obj = strtoull(argv[1], NULL, 0);
    uint64_t start = argc > 2 ? strtoull(argv[2], NULL, 0) : 0;
    uint64_t len = argc > 3 ? strtoull(argv[3], NULL, 0) : 0x400;
    std::vector<uint8_t> b(len);
    if (!rmem(obj + start, b.data(), len)) { printf("[!] read fail\n"); return 1; }
    for (uint64_t o = 0; o < len; o += 16) {
        printf("%04llx: ", (unsigned long long)(start + o));
        for (int i = 0; i < 16; i++) printf("%02x ", b[o + i]);
        printf(" | ");
        for (int i = 0; i < 16; i++) {
            uint8_t c = b[o + i];
            printf("%c", (c >= 32 && c < 127) ? c : '.');
        }
        // annotate qwords that are SIDs or ptrs
        for (int i = 0; i < 16; i += 8) {
            uint64_t v; memcpy(&v, b.data() + o + i, 8);
            if (v >= 76561197960265728ULL && v <= 76561202255233023ULL) printf("  << SID %llu", (unsigned long long)v);
        }
        printf("\n");
    }
    return 0;
}
