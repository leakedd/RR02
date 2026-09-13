// dump_klass_bp.cpp — dump the BasePlayer klass used by daemon (0x10399bac0) + follow static fields
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <unistd.h>

static mach_port_t task;
static int r64(uint64_t a, uint64_t* v) {
    mach_vm_size_t sz = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, (mach_vm_address_t)a, 8, (mach_vm_address_t)v, &sz);
    return kr == KERN_SUCCESS && sz == 8 ? 0 : -1;
}
static int r8(uint64_t a, uint8_t* v) {
    mach_vm_size_t sz = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, (mach_vm_address_t)a, 1, (mach_vm_address_t)v, &sz);
    return kr == KERN_SUCCESS && sz == 1 ? 0 : -1;
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

int main(int argc, char** argv) {
    pid_t pid = 2541;
    task_for_pid(mach_task_self(), pid, &task);
    if (!task) { printf("task_for_pid failed\n"); return 1; }
    uint64_t K = argc > 1 ? strtoull(argv[1], 0, 0) : 0x10399bac0;
    printf("[+] dump klass 0x%llx\n", K);
    uint8_t buf[0x200];
    if (rbuf(K, buf, sizeof(buf))) { printf("read fail\n"); return 1; }
    for (int off = 0; off < 0x200; off += 8) {
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
    // UC layout: static_fields @ +0xb8
    uint64_t sf = 0;
    if (!r64(K + 0xb8, &sf) && sf && ptr_ok(sf)) {
        printf("\n[klass+0xb8] static_fields = 0x%llx\n", sf);
        uint8_t b2[0x100];
        if (!rbuf(sf, b2, sizeof(b2))) {
            for (int off = 0; off < 0x100; off += 8) {
                uint64_t q;
                memcpy(&q, b2+off, 8);
                char tag[96] = "";
                if (ptr_ok(q)) {
                    char s[64];
                    cstr(q, s, 64);
                    uint64_t q2 = 0;
                    r64(q, &q2);
                    if (q2 && ptr_ok(q2)) snprintf(tag, 96, " -> \"%s\" [q]=0x%llx", s, q2);
                    else if (s[0]) snprintf(tag, 96, " -> \"%s\"", s);
                }
                printf("  SF+0x%02x : 0x%016llx%s\n", off, q, tag);
            }
        }
        // UC: entities @ sf+0x20 (wrapper encrypted), wrapper: +0x10 type, +0x18 val
        uint64_t wr = 0;
        r64(sf + 0x20, &wr);
        printf("\n[sf+0x20] entities wrapper = 0x%llx\n", wr);
        if (wr && ptr_ok(wr)) {
            uint8_t tb = 0xff;
            r8(wr + 0x10, &tb);
            uint64_t val = 0;
            r64(wr + 0x18, &val);
            printf("  [w+0x10] type=0x%02x  [w+0x18] val=0x%llx\n", tb, val);
        }
    } else {
        printf("\n[klass+0xb8] static_fields = 0 (macOS layout differs)\n");
    }
    return 0;
}
