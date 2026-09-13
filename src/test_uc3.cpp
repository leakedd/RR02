// test_uc3.cpp — single-pass: find SID@+0x718, read pm=[obj+0x340], pos=[pm+0x2F8] from SAME buffer
// Also search for the known local position float3 anywhere in the region.
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <mach/mach.h>
#include <mach/mach_vm.h>

static mach_port_t task;
static const uint64_t SID_LOCAL = 76561198984296471ULL;
static const float LX = -147.31f, LY = 30.99f, LZ = 1517.65f;
static bool isSid(uint64_t v) { return v >= 76561197960265728ULL && v < 76561202255233023ULL; }

int main() {
    pid_t pid = 2541;
    task_for_pid(mach_task_self(), pid, &task);
    if (!task) { printf("task_for_pid failed\n"); return 1; }
    printf("[+] Rust PID=%d single-pass SID@0x718 -> pm@0x340 -> pos@0x2F8\n", pid);

    mach_vm_address_t addr = 0;
    mach_vm_size_t sz = 0;
    int nsid = 0, nlocal = 0;
    while (1) {
        mach_port_t objname = 0;
        mach_msg_type_number_t cnt2 = VM_REGION_BASIC_INFO_COUNT_64;
        vm_region_basic_info_data_64_t bi;
        kern_return_t kr = mach_vm_region(task, &addr, &sz, VM_REGION_BASIC_INFO_64,
                                          (vm_region_info_t)&bi, &cnt2, &objname);
        if (kr != KERN_SUCCESS) break;
        if (!(bi.protection & VM_PROT_READ) || bi.protection & VM_PROT_EXECUTE) { addr += sz; continue; }
        if (sz > 512ULL*1024*1024) { addr += sz; continue; }
        std::vector<uint8_t> buf(sz);
        mach_vm_size_t got = 0;
        kr = mach_vm_read_overwrite(task, addr, sz, (mach_vm_address_t)buf.data(), &got);
        if (kr == KERN_SUCCESS && got == sz) {
            // 1) local float3 search
            for (uint64_t off = 0; off + 12 <= sz; off += 4) {
                float x, y, z;
                memcpy(&x, buf.data()+off, 4);
                memcpy(&y, buf.data()+off+4, 4);
                memcpy(&z, buf.data()+off+8, 4);
                if (fabsf(x-LX)<0.02f && fabsf(y-LY)<0.02f && fabsf(z-LZ)<0.02f) {
                    printf("LOCALPOS @ 0x%llx (+0x%llx) (%.2f,%.2f,%.2f)\n", addr+off, off, x, y, z);
                    if (++nlocal >= 4) break;
                }
            }
            // 2) SID @ +0x718
            for (uint64_t off = 0x718; off + 0x720 <= sz; off += 8) {
                uint64_t sid;
                memcpy(&sid, buf.data()+off, 8);
                if (!isSid(sid)) continue;
                uint64_t obj = addr + off - 0x718;
                uint64_t rel = off - 0x718; // obj offset in buf
                // pm = [obj+0x340] — read from buffer if in range
                uint64_t pm = 0;
                bool pm_ok = false;
                if (rel + 0x340 + 8 <= sz) {
                    memcpy(&pm, buf.data()+rel+0x340, 8);
                    pm_ok = true;
                }
                float pos[3] = {0,0,0};
                bool pos_ok = false;
                if (pm_ok && pm >= addr && pm + 0x2F8 + 12 <= addr + sz) {
                    memcpy(pos, buf.data() + (pm - addr) + 0x2F8, 12);
                    pos_ok = true;
                }
                const char* tag = (sid == SID_LOCAL) ? " *** LOCAL" : "";
                printf("SID %llu obj=0x%llx pm=0x%llx pos=(%.2f, %.2f, %.2f)%s\n",
                       sid, obj, pm, pos[0], pos[1], pos[2], tag);
                if (++nsid >= 40) break;
            }
        }
        addr += sz;
        if (nsid >= 40) break;
    }
    printf("[+] done: sid_hits=%d localpos_hits=%d\n", nsid, nlocal);
    return 0;
}
