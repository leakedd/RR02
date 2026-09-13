// =============================================================================
// dump_deep.cpp — structured deep dump of user object 0x68aaec980 (0x1200)
// Shows: qword hex, heap-pointer candidates, world-float candidates
// =============================================================================
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach-o/dyld.h>
#include <cstdio>
#include <cstring>
#include <cmath>
#include <cstdint>
#include <string>

static task_t g_task;
static bool rmem(uint64_t a, void* b, size_t s) {
    vm_size_t got = 0;
    return vm_read_overwrite(g_task, (vm_address_t)a, s, (vm_address_t)b, &got) == KERN_SUCCESS && (size_t)got == s;
}
static uint64_t r64(uint64_t a) { uint64_t v = 0; rmem(a, &v, 8); return v; }
static float rf(uint64_t a) { float v = 0; rmem(a, &v, 4); return v; }

static bool heapish(uint64_t v) {
    return v > 0x100000000ULL && v < 0x80000000000ULL && (v & 0x7) == 0;
}
static bool codish(uint64_t v) {
    return v > 0x100000000ULL && v < 0x400000000ULL && (v & 0x3) == 0;
}

int main(int argc, char** argv) {
    pid_t pid = 2541;
    if (argc > 1) pid = atoi(argv[1]);
    task_for_pid(mach_task_self(), pid, &g_task);
    if (!g_task) { printf("task_for_pid failed\n"); return 1; }
    setvbuf(stdout, NULL, _IONBF, 0);

    uint64_t A = 0x68aaec980ULL;
    if (argc > 2) A = strtoull(argv[2], NULL, 0);

    unsigned char buf[0x40];
    printf("deep dump 0x%llx .. +0x1200\n", (unsigned long long)A);
    for (uint64_t o = 0; o < 0x1200; o += 0x20) {
        uint64_t q0 = r64(A + o), q1 = r64(A + o + 8);
        float f0 = rf(A + o), f1 = rf(A + o + 4), f2 = rf(A + o + 8);
        float f3 = rf(A + o + 0xc), f4 = rf(A + o + 0x10), f5 = rf(A + o + 0x14);
        std::string tag;
        char t[160];
        // world-float triplet?
        if (std::isfinite(f0) && std::isfinite(f1) && std::isfinite(f2) &&
            fabsf(f0) < 5000 && fabsf(f1) < 5000 && fabsf(f2) < 5000 &&
            (fabsf(f0) > 1 || fabsf(f1) > 1 || fabsf(f2) > 1))
            snprintf(t, sizeof(t), "  F=(%7.1f,%7.1f,%7.1f)", f0, f1, f2);
        else if (heapish(q0)) snprintf(t, sizeof(t), "  PTR=0x%llx", (unsigned long long)q0);
        else if (codish(q0))  snprintf(t, sizeof(t), "  CODE=0x%llx", (unsigned long long)q0);
        else snprintf(t, sizeof(t), "  q=0x%016llx", (unsigned long long)q0);
        tag = t;
        if (q1 != 0) {
            char t2[64];
            if (heapish(q1)) snprintf(t2, sizeof(t2), " q1=0x%llx", (unsigned long long)q1);
            else snprintf(t2, sizeof(t2), " q1=%lld", (long long)q1);
            tag += t2;
        }
        printf("+0x%04llx: %s\n", (unsigned long long)o, tag.c_str());
    }
    return 0;
}
