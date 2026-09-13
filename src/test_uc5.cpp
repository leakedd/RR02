// test_uc5.cpp — single-pass scan: SID@+0x718 (userID UC layout) + read position @+0x1168
// and [[+0x340]+0x2F8] from the SAME buffer. The local hit must show (-147.31, 30.99, 1517.65).
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <unistd.h>

static mach_port_t task;
static const uint64_t SID_LOCAL = 76561198984296471ULL;
static bool isSid(uint64_t v) { return v >= 76561197960265728ULL && v < 76561202255233023ULL; }
static bool pos_ok(float* p) {
    return p[1] > 0.5f && p[1] < 2000.f && p[0] > -4000.f && p[0] < 4000.f && p[2] > -4000.f && p[2] < 4000.f;
}

int main() {
    pid_t pid = 2541;
    task_for_pid(mach_task_self(), pid, &task);
    if (!task) { printf("task_for_pid failed\n"); return 1; }
    printf("[+] single-pass SID@0x718 scan (userID UC) + pos@0x1168\n");

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
            for (size_t i = 0; i + 0x1180 <= got; i += 8) {
                uint64_t sid;
                memcpy(&sid, buf.data()+i, 8);
                if (!isSid(sid)) continue;
                uint64_t obj = addr + o + i - 0x718;
                if (obj < addr) continue;
                uint64_t rel = i - 0x718; // obj offset in buffer
                // vtable
                uint64_t vt = 0;
                memcpy(&vt, buf.data()+rel, 8);
                // position @+0x1168
                float p1[3] = {0,0,0};
                bool p1ok = rel + 0x1168 + 12 <= got;
                if (p1ok) memcpy(p1, buf.data()+rel+0x1168, 12);
                // pm @+0x340 -> pos @+0x2F8
                uint64_t pm = 0;
                float p2[3] = {0,0,0};
                bool p2ok = false;
                if (rel + 0x340 + 8 <= got) {
                    memcpy(&pm, buf.data()+rel+0x340, 8);
                    if (pm >= addr && pm + 0x2F8 + 12 <= addr + sz) {
                        // pm might be in a later chunk — only handle same-chunk via direct read
                        mach_vm_size_t sz2 = 0;
                        if (mach_vm_read_overwrite(task, pm+0x2F8, 12, (mach_vm_address_t)p2, &sz2) == KERN_SUCCESS && sz2 == 12)
                            p2ok = true;
                    }
                }
                const char* tag = (sid == SID_LOCAL) ? " *** LOCAL" : "";
                printf("SID %llu obj=0x%llx vt=0x%llx p1168=(%.2f, %.2f, %.2f)%s pm=0x%llx p2f8=(%.2f, %.2f, %.2f)%s%s\n",
                       sid, obj, vt, p1[0], p1[1], p1[2], tag, pm,
                       p2[0], p2[1], p2[2], p2ok ? "" : " (no)", pos_ok(p1) ? " POS_OK" : "");
                if (++hits >= 40) break;
            }
        }
        addr += sz;
        if (hits >= 40) break;
    }
    printf("[+] done hits=%d\n", hits);
    return 0;
}
