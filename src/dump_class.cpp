// =============================================================================
// dump_class.cpp — identify classes: for a list of binary addrs, read
// [addr] (klass ptr if vtable), [klass+0x10] (name ptr), print name string.
// Also deep-dump tail of user object (0xc40..0x1200).
// =============================================================================
#include <mach/mach.h>
#include <mach/mach_vm.h>
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

static std::string cstr(uint64_t a, int max = 96) {
    char b[128] = {0};
    if (!rmem(a, b, max)) return "?";
    std::string s;
    for (int i = 0; i < max && b[i]; i++) {
        if (b[i] >= 32 && b[i] < 127) s += b[i];
        else break;
    }
    return s;
}

static void id_class(uint64_t a) {
    uint64_t k0 = r64(a);
    uint64_t klass = k0;
    // If this is a vtable, [vtable] = Il2CppClass*
    uint64_t namep = r64(klass + 0x10);
    std::string name = cstr(namep);
    printf("  0x%llx: [0]=0x%llx [0x10]=0x%llx name='%s'\n",
           (unsigned long long)a, (unsigned long long)k0,
           (unsigned long long)namep, name.c_str());
    // static_fields at klass+0xB8
    uint64_t sf = r64(klass + 0xB8);
    printf("          [klass+0xB8]=0x%llx\n", (unsigned long long)sf);
}

int main(int argc, char** argv) {
    pid_t pid = 2541;
    if (argc > 1) pid = atoi(argv[1]);
    task_for_pid(mach_task_self(), pid, &g_task);
    if (!g_task) { printf("task_for_pid failed\n"); return 1; }
    setvbuf(stdout, NULL, _IONBF, 0);

    uint64_t addrs[] = {
        0x10399bac0ULL, 0x10399ac00ULL, 0x10399b7e0ULL, 0x103999dc0ULL,
        0x12f88ac50ULL, 0x12f88d670ULL, 0x47efd0600ULL, 0x4aadfb688ULL,
        0x132b19a40ULL, 0x68b123cc0ULL, 0x68b11b880ULL
    };
    printf("== class identification ==\n");
    for (auto a : addrs) id_class(a);

    uint64_t A = 0x68aaec980ULL;
    printf("\n== tail dump 0x%llx +0xc40..0x1200 ==\n", (unsigned long long)A);
    for (uint64_t o = 0xc40; o < 0x1200; o += 0x20) {
        uint64_t q0 = r64(A + o), q1 = r64(A + o + 8);
        float f0 = rf(A + o), f1 = rf(A + o + 4), f2 = rf(A + o + 8);
        char t[200];
        if (std::isfinite(f0) && std::isfinite(f1) && std::isfinite(f2) &&
            fabsf(f0) < 5000 && fabsf(f1) < 5000 && fabsf(f2) < 5000 &&
            (fabsf(f0) > 1 || fabsf(f1) > 1 || fabsf(f2) > 1))
            snprintf(t, sizeof(t), "  F=(%7.1f,%7.1f,%7.1f)", f0, f1, f2);
        else if (q0 > 0x100000000ULL && q0 < 0x80000000000ULL && (q0 & 7) == 0)
            snprintf(t, sizeof(t), "  PTR=0x%llx", (unsigned long long)q0);
        else if (q0 != 0)
            snprintf(t, sizeof(t), "  q=0x%016llx", (unsigned long long)q0);
        else t[0] = 0;
        if (q1 > 0x100000000ULL && q1 < 0x80000000000ULL && (q1 & 7) == 0) {
            char t2[40]; snprintf(t2, sizeof(t2), " q1=0x%llx", (unsigned long long)q1);
            strncat(t, t2, sizeof(t) - strlen(t) - 1);
        }
        printf("+0x%04llx:%s\n", (unsigned long long)o, t);
    }
    return 0;
}
