// =============================================================================
// dump_class2.cpp — identify classes from binary addrs seen in player objects.
// Tries: addr as klass (name@+0x10, static_fields@+0xB8), and addr as vtable
// (klass = [addr], then same). Prints readable names.
// =============================================================================
#include <cstdio>
#include <cstdint>
#include <cstring>
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

static void print_name(uint64_t p) {
    if (!p) { printf("null"); return; }
    char buf[96] = {};
    if (rmem(p, buf, sizeof(buf) - 1)) {
        bool printable = true;
        for (int i = 0; i < 95; i++) {
            if (buf[i] == 0) break;
            if (buf[i] < 32 || buf[i] > 126) { printable = false; break; }
        }
        if (printable) printf("%s", buf);
        else printf("(non-ascii: %02x %02x %02x %02x %02x...)", (unsigned char)buf[0], (unsigned char)buf[1], (unsigned char)buf[2], (unsigned char)buf[3], (unsigned char)buf[4]);
    } else printf("(unreadable)");
}

static void probe(const char* tag, uint64_t a) {
    uint64_t v0 = r64(a);
    uint64_t namep_direct = r64(a + 0x10);
    uint64_t sf_direct = r64(a + 0xB8);
    uint64_t namep_via = r64(v0 + 0x10);
    uint64_t sf_via = r64(v0 + 0xB8);
    printf("[%s] 0x%llx\n", tag, (unsigned long long)a);
    printf("  [0]=0x%llx\n", (unsigned long long)v0);
    printf("  direct: name@+0x10 -> ", (unsigned long long)namep_direct);
    print_name(namep_direct); printf("  | sf@+0xB8=0x%llx\n", (unsigned long long)sf_direct);
    printf("  via[0]: name -> ");
    print_name(namep_via); printf("  | sf=0x%llx\n", (unsigned long long)sf_via);
}

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

    probe("slot-a", 0x10399bac0);
    probe("slot-b", 0x10399bda0);
    probe("slot-c", 0x10399b7e0);
    probe("slot-d", 0x10399b500);
    probe("slot-e", 0x103999dc0);
    probe("slot-f", 0x1039ba818);
    // also: vtable dyn seen in peer pairs
    probe("dyn-12f890250", 0x12f890250);
    probe("dyn-12f8900d0", 0x12f8900d0);
    probe("dyn-12f88d670", 0x12f88d670);
    probe("dyn-12f8a0b70", 0x12f8a0b70);
    // sub-obj heap probes from user object
    probe("sub-132b19a40", 0x132b19a40);
    probe("sub-68b123cc0", 0x68b123cc0);
    return 0;
}
