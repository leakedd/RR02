// test_pm_offsets.cpp — scan SID@+0x1b0 (same as daemon Phase A), then test all
// PlayerModel offsets on each player object to find world positions
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <map>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <unistd.h>

static mach_port_t task;
static const uint64_t BP_VTABLE = 0x10399bac0ULL;
static const uint64_t SID_OFF = 0x1b0;
static const int POS_DIRECT = 0x1168; // daemon direct pos

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
static bool isSid(uint64_t v) { return v >= 76561197960265728ULL && v < 76561202255233023ULL; }
static bool pos_ok(float* p) {
    return p[1] > 0.5f && p[1] < 2000.f && fabsf(p[0]) < 4000.f && fabsf(p[2]) < 4000.f;
}

int main() {
    pid_t pid = 2541;
    task_for_pid(mach_task_self(), pid, &task);
    if (!task) { printf("task_for_pid failed\n"); return 1; }
    printf("[+] Phase A scan (SID@0x1b0 + vtable 0x10399bac0)\n");

    std::vector<uint8_t> buf(4 * 1024 * 1024);
    mach_vm_address_t addr = 0;
    mach_vm_size_t sz = 0;
    std::map<uint64_t, uint64_t> by_sid; // sid -> obj
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
                uint64_t v;
                memcpy(&v, buf.data()+i, 8);
                if (!isSid(v)) continue;
                uint64_t obj = addr + o + i - SID_OFF;
                if (obj < addr) continue;
                uint64_t vt = 0;
                if (r64(obj, &vt) || vt != BP_VTABLE) continue;
                if (!by_sid.count(v)) by_sid[v] = obj;
            }
        }
        addr += sz;
    }
    printf("[+] %zu players found\n", by_sid.size());
    if (by_sid.empty()) { printf("No players!\n"); return 1; }

    // Test all PlayerModel offsets on each player
    const int PM_OFFSETS[] = {0x6F0, 0x340, 0x508, 0x4a8, 0x330, 0x3a0};
    const int N_PM = 6;
    const uint64_t SID_LOCAL = 76561198984296471ULL;
    
    for (auto& [sid, obj] : by_sid) {
        const char* tag = (sid == SID_LOCAL) ? " *** LOCAL" : "";
        float dpos[3];
        rbuf(obj + POS_DIRECT, dpos, 12);
        printf("\nSID %llu obj=0x%llx%s\n", sid, obj, tag);
        printf("  direct @+0x%04x = (%.2f, %.2f, %.2f)\n", POS_DIRECT, dpos[0], dpos[1], dpos[2]);
        for (int j = 0; j < N_PM; j++) {
            int off = PM_OFFSETS[j];
            uint64_t pm = 0;
            if (r64(obj + off, &pm) || !pm) continue;
            float p[3];
            if (rbuf(pm + 0x2F8, p, 12)) continue;
            printf("  pm@+0x%03x=0x%llx -> pos@0x2F8 = (%.2f, %.2f, %.2f) %s\n",
                   off, pm, p[0], p[1], p[2], pos_ok(p) ? "OK" : "");
        }
        // also read SID at +0x718 for validation
        uint64_t sid718 = 0;
        r64(obj + 0x718, &sid718);
        printf("  sid@0x718 = %llu\n", sid718);
        // displayName
        uint64_t dn = 0;
        r64(obj + 0x2D8, &dn); // Cl1k: DisplayName = 0x2D8
        if (dn) {
            char name[64];
            cstr(dn + 0x10, name, 64); // UnityString: length@0x10, chars@0x14
            uint32_t len = 0;
            mach_vm_size_t sz2 = 0;
            mach_vm_read_overwrite(task, dn + 0x10, 4, (mach_vm_address_t)&len, &sz2);
            if (len > 0 && len < 64) {
                uint16_t wbuf[64];
                mach_vm_read_overwrite(task, dn + 0x14, len*2, (mach_vm_address_t)wbuf, &sz2);
                char out[65]; int n = 0;
                for (uint32_t k = 0; k < len && k < 32; k++) {
                    if (wbuf[k] >= 32 && wbuf[k] < 127) out[n++] = (char)wbuf[k];
                }
                out[n] = 0;
                printf("  displayName = \"%s\"\n", out);
            }
        }
    }
    return 0;
}
