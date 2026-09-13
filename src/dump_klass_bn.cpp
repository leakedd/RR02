// dump_klass_bn.cpp — raw dump of BaseNetworkable Il2CppClass (0x103a80990) looking for
// static_fields pointer + wrapper (ClientEntities). Prints all qwords, follows plausible ptrs.
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <unistd.h>

static mach_port_t task;
static int r64(uint64_t a, uint64_t* v) {
    mach_vm_size_t sz = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, (mach_vm_address_t)a, 8, (mach_vm_address_t)v, &sz);
    return kr == KERN_SUCCESS && sz == 8 ? 0 : -1;
}
static int rbuf(uint64_t a, void* b, size_t n) {
    mach_vm_size_t sz = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, (mach_vm_address_t)a, n, (mach_vm_address_t)b, &sz);
    return kr == KERN_SUCCESS && sz == n ? 0 : -1;
}
static void cstr(uint64_t a, char* out, size_t n) {
    out[0] = 0;
    uint8_t b[64];
    if (rbuf(a, b, 63)) { snprintf(out, n, "<unreadable>"); return; }
    size_t i = 0;
    while (i < n-1 && b[i] >= 32 && b[i] < 127) { out[i] = b[i]; i++; }
    out[i] = 0;
}
static bool ptr_ok(uint64_t p) { return p > 0x100000000ULL && p < 0x40000000000ULL; }

int main() {
    pid_t pid = 2541;
    task_for_pid(mach_task_self(), pid, &task);
    if (!task) { printf("task_for_pid failed\n"); return 1; }
    const uint64_t K = 0x103a80990; // BaseNetworkable klass
    printf("[+] dump klass 0x%llx\n", K);
    uint8_t buf[0x400];
    if (rbuf(K, buf, sizeof(buf))) { printf("read fail\n"); return 1; }
    for (int off = 0; off < 0x400; off += 8) {
        uint64_t q;
        memcpy(&q, buf+off, 8);
        char tag[96] = "";
        if (ptr_ok(q)) {
            char s[64];
            cstr(q, s, 64);
            uint64_t q2 = 0;
            r64(q, &q2);
            if (q2 && ptr_ok(q2)) snprintf(tag, 96, " -> \"%s\" [q]=0x%llx", s, q2);
            else if (s[0]) snprintf(tag, 96, " -> \"%s\"", s);
        }
        printf("  +0x%03x : 0x%016llx%s\n", off, q, tag);
    }
    return 0;
}
