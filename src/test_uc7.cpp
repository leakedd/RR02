// test_uc7.cpp — find BasePlayer by userID@+0x718 (UC layout), then locate the local world
// position (-147.31,30.99,1517.65) inside obj / playerModel. Validates macOS field layout.
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <unistd.h>

static mach_port_t task;
static const uint64_t SID_LOCAL = 76561198984296471ULL;
static const float LX=-147.31f, LY=30.99f, LZ=1517.65f;
static bool isSid(uint64_t v) { return v >= 76561197960265728ULL && v < 76561202255233023ULL; }

static int r64(uint64_t a, uint64_t* v) {
    mach_vm_size_t sz = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, (mach_vm_address_t)a, 8, (mach_vm_address_t)v, &sz);
    return kr == KERN_SUCCESS && sz == 8 ? 0 : -1;
}
static void cstr(uint64_t a, char* out, size_t n) {
    out[0] = 0;
    uint8_t b[64];
    mach_vm_size_t sz = 0;
    if (mach_vm_read_overwrite(task, a, 63, (mach_vm_address_t)b, &sz) != KERN_SUCCESS || sz != 63) return;
    size_t i = 0;
    while (i < n-1 && b[i] >= 32 && b[i] < 127) { out[i] = b[i]; i++; }
    out[i] = 0;
}
static void find_pos(uint64_t a, size_t n, const char* label) {
    std::vector<uint8_t> buf(n);
    mach_vm_size_t got = 0;
    if (mach_vm_read_overwrite(task, a, n, (mach_vm_address_t)buf.data(), &got) != KERN_SUCCESS || got != n) {
        printf("      %s: unreadable\n", label);
        return;
    }
    int hits = 0;
    for (size_t off = 0; off + 12 <= n && hits < 4; off += 4) {
        float x, y, z;
        memcpy(&x, buf.data()+off, 4);
        memcpy(&y, buf.data()+off+4, 4);
        memcpy(&z, buf.data()+off+8, 4);
        if (fabsf(x-LX)<0.05f && fabsf(y-LY)<0.05f && fabsf(z-LZ)<0.05f) {
            printf("      %s: pos @ +0x%zx = (%.2f, %.2f, %.2f)\n", label, off, x, y, z);
            hits++;
        }
    }
    if (!hits) printf("      %s: no pos match\n", label);
}

int main() {
    pid_t pid = 2541;
    task_for_pid(mach_task_self(), pid, &task);
    if (!task) { printf("task_for_pid failed\n"); return 1; }
    printf("[+] scan userID@+0x718 (SID local) + locate local pos\n");

    std::vector<uint8_t> buf(4 * 1024 * 1024);
    mach_vm_address_t addr = 0;
    mach_vm_size_t sz = 0;
    int hits = 0;
    while (1) {
        mach_port_t objname = 0;
        mach_msg_type_number_t cnt2 = VM_REGION_BASIC_INFO_COUNT_64;
        vm_region_basic_info_data_64_t bi;
        kern_return_t kr = mach_vm_region(task, &addr, &sz, VM_REGION_BASIC_INFO_64,
                                          (vm_region_info_t)&bi, &cnt2, &objname);
        if (kr != KERN_SUCCESS) break;
        if (!(bi.protection & VM_PROT_READ) || bi.protection & VM_PROT_EXECUTE) { addr += sz; continue; }
        if (sz > 512ULL*1024*1024) { addr += sz; continue; }
        for (uint64_t o = 0; o < sz; o += buf.size()) {
            uint64_t tr = std::min((uint64_t)buf.size(), sz - o);
            mach_vm_size_t got = 0;
            if (mach_vm_read_overwrite(task, addr + o, tr, (mach_vm_address_t)buf.data(), &got) != KERN_SUCCESS) break;
            for (size_t i = 0; i + 8 <= got; i += 8) {
                uint64_t sid;
                memcpy(&sid, buf.data()+i, 8);
                if (sid != SID_LOCAL) continue;
                uint64_t obj = addr + o + i - 0x718;
                if (obj < addr) continue;
                printf("HIT sid@0x%llx obj=0x%llx\n", addr+o+i, obj);
                uint64_t vt = 0, pm = 0;
                r64(obj, &vt);
                r64(obj + 0x340, &pm);
                printf("  vt=0x%llx pm=0x%llx\n", vt, pm);
                char s[64];
                cstr(vt + 0x10, s, 64); printf("  klass name = \"%s\"\n", s);
                if (pm) { cstr(pm, s, 64); }
                // find local pos in obj (0x4000) and pm (0x3000)
                find_pos(obj - 0x100, 0x4200, "obj");
                if (pm) find_pos(pm - 0x100, 0x3200, "pm");
                if (++hits >= 6) break;
            }
        }
        addr += sz;
        if (hits >= 6) break;
    }
    printf("[+] done hits=%d\n", hits);
    return 0;
}
