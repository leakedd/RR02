// =============================================================================
// test_transform2.cpp — CORRECT Unity Transform chain:
//   managed_transform (+0x10 = m_CachedPtr) -> native (+0x28 = TransformData*)
//   -> (+0x90 = root world pos)
// For each player obj: find (Transform klass 0x12f8a0b70, ptr) pairs, walk chain.
// =============================================================================
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <mach/mach.h>
#include <unistd.h>

static mach_port_t task;
static uint64_t r64(uint64_t a) { uint64_t v = 0; mach_msg_type_number_t s = 0; vm_read(task, (vm_address_t)a, 8, (vm_offset_t*)&v, &s); return v; }
static float rf(uint64_t a) { uint32_t v = 0; mach_msg_type_number_t s = 0; vm_read(task, (vm_address_t)a, 4, (vm_offset_t*)&v, &s); float f; __builtin_memcpy(&f, &v, 4); return f; }
static bool in_world(float x, float y, float z) {
    return std::isfinite(x) && std::isfinite(y) && std::isfinite(z)
        && fabsf(x) < 5000 && fabsf(z) < 5000 && y > -100 && y < 900
        && sqrtf(x*x + z*z) > 150.0f;
}

int main() {
    if (task_for_pid(mach_task_self(), 2541, &task) != KERN_SUCCESS) { printf("tfp fail\n"); return 1; }
    uint64_t objs[] = {0x68aaec980, 0x690a6c0e0, 0x690a17740, 0x7af7d84c0, 0x68531e2a0, 0x6887a7d00, 0x68985f980, 0x690aaace0, 0x6869b3060};
    const char* names[] = {"user", "p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8"};
    const uint64_t K_TRANSFORM = 0x12f8a0b70; // managed Transform vtable (heap)
    for (int i = 0; i < 9; i++) {
        printf("== %s 0x%llx ==\n", names[i], (unsigned long long)objs[i]);
        int ntr = 0, nok = 0;
        for (uint64_t off = 0x20; off < 0x3000; off += 8) {
            uint64_t v = r64(objs[i] + off);
            if (v != K_TRANSFORM) continue;
            uint64_t mng = r64(objs[i] + off + 0x10); // ptr (slot +0x10)
            if (mng < 0x10000 || mng > 0x7fffffffffffULL) continue;
            ntr++;
            uint64_t nat = r64(mng + 0x10);          // m_CachedPtr
            uint64_t td  = r64(nat + 0x28);          // TransformData*
            if (td < 0x10000 || td > 0x7fffffffffffULL) { printf("  t@+0x%llx mng=0x%llx nat=0x%llx td=INV\n", (unsigned long long)off, (unsigned long long)mng, (unsigned long long)nat); continue; }
            float x = rf(td + 0x90), y = rf(td + 0x94), z = rf(td + 0x98);
            if (in_world(x, y, z)) { nok++; printf("  t@+0x%llx -> WORLD (%.1f, %.1f, %.1f)\n", (unsigned long long)off, x, y, z); }
            else printf("  t@+0x%llx -> (%.1f, %.1f, %.1f)\n", (unsigned long long)off, x, y, z);
        }
        printf("  [%d transforms, %d world]\n", ntr, nok);
    }
    return 0;
}
