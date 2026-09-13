// scan_entlist.cpp — scan for BaseNetworkable entity list BufferList directly
// BufferList pattern: [B+0x10]=ptr P, [B+0x18]=count C (10..50000), entries [P+0x28+8*i]=entity
// Validate: entity -> klass -> name must be readable (contains "Base" or known class)
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <unistd.h>

static mach_port_t task;
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
static int rbuf(uint64_t a, void* b, size_t n) {
    mach_vm_size_t sz = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, (mach_vm_address_t)a, n, (mach_vm_address_t)b, &sz);
    return kr == KERN_SUCCESS && sz == n ? 0 : -1;
}
static bool ptr_ok(uint64_t p) { return p > 0x100000000ULL && p < 0x40000000000ULL; }
static void cstr(uint64_t a, char* out, size_t n) {
    out[0] = 0;
    uint8_t b[64];
    if (rbuf(a, b, 63)) return;
    size_t i = 0;
    while (i < n-1 && b[i] >= 32 && b[i] < 127 && b[i]) { out[i] = b[i]; i++; }
    out[i] = 0;
}

int main() {
    pid_t pid = 2541;
    task_for_pid(mach_task_self(), pid, &task);
    if (!task) { printf("task_for_pid failed\n"); return 1; }
    printf("[+] scanning for entity list BufferList (Cl1k pattern)\n");

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
                uint64_t q;
                memcpy(&q, buf.data()+i, 8);
                if (!ptr_ok(q)) continue;
                // Potential array ptr — check if preceding u32 is a reasonable count
                if (i < 8) continue;
                uint32_t cnt;
                memcpy(&cnt, buf.data()+i-8, 4);
                if (cnt < 20 || cnt > 50000) continue;
                // Validate: try reading 3 entity entries from [q + 0x28]
                uint64_t ents[3] = {0};
                if (rbuf(q + 0x28, ents, 24)) continue;
                int valid_ents = 0;
                for (int j = 0; j < 3; j++) {
                    if (!ptr_ok(ents[j])) continue;
                    uint64_t klass = 0;
                    if (r64(ents[j], &klass) || !ptr_ok(klass)) continue;
                    char name[64];
                    cstr(klass + 0x10, name, 64);
                    if (name[0] >= 'A' && name[0] <= 'Z') valid_ents++;
                }
                if (valid_ents < 2) continue;
                // FOUND!
                uint64_t obj = addr + o + i - 8; // the BufferList object (cnt at +0x18, arr at +0x10 from obj)
                // Actually the q is at array offset from the BufferList object.
                // We found: q = arr ptr, cnt just before (8 bytes back). The BufferList object
                // is where cnt is at offset +0x18 and arr is at +0x20? Let's verify.
                // Cl1k: BufferList_Array = 0x10, BufferList_Count = 0x18
                // That means [obj+0x10] = arr, [obj+0x18] = count.
                // We found cnt at offset i-0 (from addr+o), and arr at i-0+8.
                // So the obj would be at (addr+o+i) - 0x18 = the assumed struct base.
                uint64_t candidate_obj = addr + o + i - 8 - 0x10; // hmm off by 8?
                printf("*** HIT #%d: bufobj_candidate=0x%llx arr=0x%llx cnt=%u\n", ++hits, candidate_obj, q, cnt);
                printf("    ents: ");
                for (int j = 0; j < 3 && j < (int)cnt; j++) {
                    uint64_t ent = 0;
                    if (r64(q + 0x28 + 8*j, &ent)) break;
                    uint64_t klass = 0;
                    r64(ent, &klass);
                    char name[64];
                    cstr(klass + 0x10, name, 64);
                    printf("0x%llx:\"%s\" ", ent, name);
                    // Try reading SID and position from this entity
                    if (name[0]) {
                        uint64_t sid = 0;
                        r64(ent + 0x718, &sid);
                        uint64_t pm = 0;
                        r64(ent + 0x6F0, &pm); // Cl1k: BasePlayer.PlayerModel = 0x6F0
                        float pos[3] = {0};
                        if (pm) rbuf(pm + 0x2F8, pos, 12); // PlayerModel.Position = 0x2F8
                        if (sid) printf("SID=%llu pos=(%.2f,%.2f,%.2f)", sid, pos[0], pos[1], pos[2]);
                    }
                }
                printf("\n");
                if (hits >= 10) break;
            }
            if (hits >= 10) break;
        }
        addr += sz;
        if (hits >= 10) break;
    }
    printf("[+] done hits=%d\n", hits);
    return 0;
}
