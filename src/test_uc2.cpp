// test_uc2.cpp — find BasePlayer by userID@+0x718 (UC layout) and verify fields
// If [obj+0x718]==SID and [[obj+0x340]+0x2F8]==local pos, UC layout works on macOS
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach/task_info.h>
#include <unistd.h>

static mach_port_t task;
static uint64_t base; // image base
static const uint64_t SID_LOCAL = 76561198984296471ULL;

static int r64(uint64_t a, uint64_t* v) {
    mach_vm_size_t sz = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, (mach_vm_address_t)a, 8, (mach_vm_address_t)v, &sz);
    return kr == KERN_SUCCESS && sz == 8 ? 0 : -1;
}
static int r32(uint64_t a, uint32_t* v) {
    mach_vm_size_t sz = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, (mach_vm_address_t)a, 4, (mach_vm_address_t)v, &sz);
    return kr == KERN_SUCCESS && sz == 4 ? 0 : -1;
}
static int rf(uint64_t a, float* f, int n) {
    mach_vm_size_t sz = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, (mach_vm_address_t)a, n*4, (mach_vm_address_t)f, &sz);
    return kr == KERN_SUCCESS && sz == (mach_vm_size_t)(n*4) ? 0 : -1;
}
static bool isSid(uint64_t v) { return v >= 76561197960265728ULL && v < 76561202255233023ULL; }

int main() {
    pid_t pid = 2541;
    task_for_pid(mach_task_self(), pid, &task);
    if (!task) { printf("task_for_pid failed\n"); return 1; }
    printf("[+] Rust PID=%d\n", pid);

    // find image base via task info
    struct task_dyld_info info;
    mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
    if (task_info(task, TASK_DYLD_INFO, (task_info_t)&info, &cnt) == KERN_SUCCESS)
        base = (uint64_t)info.all_image_info_addr;
    printf("[+] dyld info addr=0x%llx\n", base);

    // walk regions, search SID at +0x718
    mach_vm_address_t addr = 0;
    mach_vm_size_t sz = 0;
    int found = 0;
    uint64_t t0 = 0;
    while (1) {
        mach_port_t objname = 0;
        mach_msg_type_number_t cnt2 = VM_REGION_BASIC_INFO_COUNT_64;
        vm_region_basic_info_data_64_t bi;
        kern_return_t kr = mach_vm_region(task, &addr, &sz, VM_REGION_BASIC_INFO_64,
                                          (vm_region_info_t)&bi, &cnt2, &objname);
        if (kr != KERN_SUCCESS) break;
        if (!(bi.protection & VM_PROT_READ) || bi.protection & VM_PROT_EXECUTE) { addr += sz; continue; }
        if (sz > 512ULL*1024*1024) { addr += sz; continue; }
        // read region, scan for SID followed by structure
        std::vector<uint8_t> buf(sz);
        mach_vm_size_t got = 0;
        kr = mach_vm_read_overwrite(task, addr, sz, (mach_vm_address_t)buf.data(), &got);
        if (kr == KERN_SUCCESS && got == sz) {
            for (uint64_t off = 0; off + 0x720 <= sz; off += 8) {
                uint64_t sid;
                memcpy(&sid, buf.data()+off, 8);
                if (!isSid(sid)) continue;
                uint64_t obj = addr + off - 0x718;
                // verify: [obj+0x340] playerModel -> [pm+0x2F8] plausible pos
                uint64_t pm;
                if (r64(obj+0x340, &pm) || !pm) continue;
                float pos[3];
                if (rf(pm+0x2F8, pos, 3)) continue;
                float y = pos[1];
                if (!(y > 0.5f && y < 2000.f)) continue;
                printf("HIT obj=0x%llx sid=%llu pm=0x%llx pos=(%.2f, %.2f, %.2f)\n",
                       obj, sid, pm, pos[0], pos[1], pos[2]);
                if (++found >= 16) break;
            }
        }
        addr += sz;
        if (found >= 16) break;
    }
    printf("[+] scan done, found=%d\n", found);
    return 0;
}
