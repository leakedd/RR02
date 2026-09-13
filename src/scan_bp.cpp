// scan_bp.cpp — scan heap for BasePlayer objects by klass name, then read SID + position
// Cl1k offsets: BasePlayer.PlayerModel=0x6F0, PlayerModel.Position=0x2F8, userID=0x718
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <set>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <unistd.h>

static mach_port_t task;
static int r64(uint64_t a, uint64_t* v) {
    mach_vm_size_t sz = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, (mach_vm_address_t)a, 8, (mach_vm_address_t)v, &sz);
    return kr == KERN_SUCCESS && sz == 8 ? 0 : -1;
}
static int rbuf(uint64_t a, void* b, size_t n) {
    mach_vm_size_t sz = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, (mach_vm_address_t)a, n, (mach_vm_address_t)b, &sz);
    return kr == KERN_SUCCESS && sz == n ? 0 : -1;
}
static void cstr(uint64_t a, char* out, size_t n) {
    out[0] = 0; uint8_t b[64];
    mach_vm_size_t sz = 0;
    if (mach_vm_read_overwrite(task, a, 63, (mach_vm_address_t)b, &sz) != KERN_SUCCESS) return;
    size_t i = 0;
    while (i < n-1 && i < (size_t)sz && b[i] >= 32 && b[i] < 127 && b[i]) out[i]=b[i], i++;
    out[i]=0;
}
static bool ptr_ok(uint64_t p) { return p > 0x100000000ULL && p < 0x40000000000ULL; }
static bool isSid(uint64_t v) { return v >= 76561197960265728ULL && v < 76561202255233023ULL; }
static bool pos_ok(float* p) {
    return p[1] > 0.5f && p[1] < 2000.f && fabsf(p[0]) < 4000.f && fabsf(p[2]) < 4000.f && (p[2] != 0.0f || p[0] != 100.f);
}

int main() {
    pid_t pid = 2541;
    task_for_pid(mach_task_self(), pid, &task);
    if (!task) { printf("task_for_pid failed\n"); return 1; }
    printf("[+] scanning heap for BasePlayer objects by klass name\n");

    std::vector<uint8_t> buf(4 * 1024 * 1024);
    mach_vm_address_t addr = 0;
    mach_vm_size_t sz = 0;
    std::set<uint64_t> seen_sids;
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
                uint64_t ent = addr + o + i; // potential entity ptr
                // [ent] should be klass ptr
                uint64_t klass = q;
                if (!ptr_ok(klass)) continue;
                char name[64];
                cstr(klass + 0x10, name, 64);
                if (strncmp(name, "BasePlayer", 10) != 0) continue;
                // Found a BasePlayer klass reference — ent = entity object
                uint64_t sid = 0;
                r64(ent + 0x718, &sid);
                if (!isSid(sid)) continue;
                uint64_t pm = 0;
                r64(ent + 0x6F0, &pm);  // Cl1k: BasePlayer.PlayerModel = 0x6F0
                float pos[3] = {0,0,0};
                if (pm) rbuf(pm + 0x2F8, pos, 12);  // Cl1k: PlayerModel.Position = 0x2F8
                if (!pos_ok(pos)) {
                    // try alternative playerModel offsets from damianskater threads
                    uint64_t pm2 = 0;
                    r64(ent + 0x340, &pm2);
                    if (pm2) rbuf(pm2 + 0x2F8, pos, 12);
                }
                if (!pos_ok(pos)) continue;
                if (seen_sids.count(sid)) continue;
                seen_sids.insert(sid);
                printf("BP 0x%llx klass=0x%llx \"%s\" sid=%llu pm=0x%llx pos=(%.2f,%.2f,%.2f)\n",
                       ent, klass, name, sid, pm, pos[0], pos[1], pos[2]);
                if (++hits >= 20) goto done;
            }
        }
        addr += sz;
    }
done:
    printf("[+] found %d BasePlayer objects\n", hits);
    return 0;
}
