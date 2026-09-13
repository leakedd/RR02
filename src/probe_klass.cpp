// =============================================================================
// probe_klass.cpp — self-derive field offsets from live Il2CppClass
// klass = [0x10399bac0] (vtable[0] -> Il2CppClass, per memory note)
// Il2CppClass.fields -> Il2CppFieldInfo[] { name(8) type(8) parent(8) off(4) tok(4) }
// =============================================================================
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <mach/mach.h>

static mach_port_t task;
static uint64_t r64(uint64_t a) {
    uint64_t v = 0; mach_msg_type_number_t sz = 0;
    vm_read(task, (vm_address_t)a, 8, (vm_offset_t*)&v, &sz);
    return v;
}
static uint32_t r32(uint64_t a) {
    uint32_t v = 0; mach_msg_type_number_t sz = 0;
    vm_read(task, (vm_address_t)a, 4, (vm_offset_t*)&v, &sz);
    return v;
}
static bool read_str(uint64_t a, char* out, int max) {
    mach_msg_type_number_t sz = 0; char buf[512] = {0};
    if (vm_read(task, (vm_address_t)a, (mach_msg_type_number_t)(max < 511 ? max : 511), (vm_offset_t*)buf, &sz) != KERN_SUCCESS) return false;
    for (int i = 0; i < (int)sz; i++) {
        if (buf[i] < 0x20 || buf[i] > 0x7e) { buf[i] = 0; break; }
    }
    strncpy(out, buf, max); return out[0] != 0;
}

int main() {
    if (task_for_pid(mach_task_self(), 2541, &task) != KERN_SUCCESS) { printf("task_for_pid failed\n"); return 1; }
    const uint64_t IMG_LO = 0x100000000ULL, IMG_HI = 0x120000000ULL;
    uint64_t vtable = 0x10399bac0;
    uint64_t klass = r64(vtable);
    printf("vtable=0x%llx klass=0x%llx\n", (unsigned long long)vtable, (unsigned long long)klass);
    if (!klass) return 1;

    // klass name @ +0x10 (observed layout)
    uint64_t np = r64(klass + 0x10);
    char nm[256] = {0};
    if (read_str(np, nm, 200)) printf("klass name @+0x10: '%s'\n", nm);
    // also try @+0x0 and @+0x8 as name ptrs
    for (int off : {0, 8, 0x10, 0x18, 0x20}) {
        uint64_t p = r64(klass + off);
        char s[256] = {0};
        if (p > IMG_LO && p < IMG_HI && read_str(p, s, 200)) printf("  name-ptr @+0x%02x -> '%s'\n", off, s);
    }

    // scan klass for a fields-array pointer: qword v in image, [v] = char* in image
    for (int koff = 0; koff < 0x400; koff += 8) {
        uint64_t v = r64(klass + koff);
        if (v < IMG_LO || v > IMG_HI) continue;
        uint64_t first_name = r64(v);
        if (first_name < IMG_LO || first_name > IMG_HI) continue;
        char s[256] = {0};
        if (!read_str(first_name, s, 200)) continue;
        if (s[0] < 0x20) continue;
        // looks like a field array: iterate entries of 0x20 bytes
        printf("\nFIELDS ARRAY candidate @ klass+0x%03x -> 0x%llx (first name '%s')\n", koff, (unsigned long long)v, s);
        for (int i = 0; i < 400; i++) {
            uint64_t e = v + (uint64_t)i * 0x20;
            uint64_t np2 = r64(e);
            if (np2 < IMG_LO || np2 > IMG_HI) { printf("  [%d] end (name ptr 0x%llx out of image)\n", i, (unsigned long long)np2); break; }
            char f[256] = {0};
            if (!read_str(np2, f, 200) || f[0] < 0x20) { printf("  [%d] end (unreadable name)\n", i); break; }
            int32_t off = (int32_t)r32(e + 0x18);
            uint32_t tok = r32(e + 0x1c);
            printf("  [%2d] off=0x%04x tok=0x%08x name='%s'\n", i, (unsigned)off, tok, f);
        }
        break; // first valid candidate only
    }
    return 0;
}
