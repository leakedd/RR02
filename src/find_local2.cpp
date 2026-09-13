// =============================================================================
// find_local2.cpp — find LocalPlayer: static ptrs to VALID BasePlayer objects
// =============================================================================
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>
#include <map>
#include <set>
#include <algorithm>

static task_t g_task = 0;
static const uint64_t VTABLE = 0x10399bac0ULL;   // BasePlayer runtime vtable (Aug 2026)
static const uint64_t SID_OFF = 0x1b0;           // SteamID offset in object

static void find_rust() {
    pid_t pids[8192]; int n = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    for (int i = 0; i < n / (int)sizeof(pid_t); i++) {
        if (!pids[i]) continue; char path[PROC_PIDPATHINFO_MAXSIZE] = {};
        if (proc_pidpath(pids[i], path, sizeof(path)) > 0 && strstr(path, "RustClient")) {
            task_for_pid(mach_task_self(), pids[i], &g_task);
            printf("[+] Rust PID=%d task=0x%x\n", pids[i], g_task);
            return;
        }
    }
    printf("[!] Rust process not found\n"); exit(1);
}

static uint64_t rd64(uint64_t a) {
    uint64_t v = 0; mach_vm_size_t got = 0;
    if (mach_vm_read_overwrite(g_task, a, 8, (vm_address_t)&v, &got) != KERN_SUCCESS || got != 8) return 0;
    return v;
}

int main() {
    find_rust();
    struct Rg { uint64_t s, e; };
    std::vector<Rg> all;
    uint64_t a = 0; mach_vm_size_t sz = 0;
    while (1) {
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = 0;
        if (mach_vm_region(g_task, &a, &sz, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &cnt, &obj) != KERN_SUCCESS) break;
        if (info.protection & VM_PROT_WRITE) all.push_back({a, a + sz});
        a += sz;
    }
    printf("[+] %zu writable regions\n", all.size());

    // Pass 1: SID scan, then obj = sid_addr - 0x1b0, verify vtable (same as radar_live)
    std::vector<uint8_t> buf(4 * 1024 * 1024);
    std::set<uint64_t> objs;   // valid BasePlayer object addrs
    std::map<uint64_t, uint64_t> obj_sid;
    for (auto& r : all) {
        uint64_t rs = r.e - r.s;
        if (rs > 512ULL * 1024 * 1024) continue;
        for (uint64_t o = 0; o < rs; o += buf.size()) {
            uint64_t tr = std::min((uint64_t)buf.size(), rs - o);
            mach_vm_size_t got = 0;
            if (mach_vm_read_overwrite(g_task, r.s + o, tr, (vm_address_t)buf.data(), &got) != KERN_SUCCESS) break;
            for (size_t i = 0; i + 8 <= (size_t)got; i += 8) {
                uint64_t v; memcpy(&v, buf.data() + i, 8);
                if (!(v >= 76561197960265728ULL && v <= 76561202255233023ULL)) continue;
                uint64_t obj_addr = r.s + o + i - 0x1b0;
                if (obj_addr < r.s) continue;
                uint64_t vt = rd64(obj_addr);
                if (vt != VTABLE) continue;
                objs.insert(obj_addr);
                obj_sid[obj_addr] = v;
            }
        }
    }
    printf("[+] %zu valid BasePlayer objects (vtable match + SID)\n", objs.size());

    // Pass 2: scan static regions (< 8GB) for ptrs to those objects
    printf("\n[*] Scanning static regions (< 8GB) for ptrs to valid player objects:\n");
    std::set<uint64_t> seen;
    int found = 0;
    for (auto& r : all) {
        if (r.s >= 0x200000000ULL) continue;
        if (r.e - r.s > 256ULL * 1024 * 1024) continue;
        for (uint64_t o = 0; o < r.e - r.s; o += buf.size()) {
            uint64_t tr = std::min((uint64_t)buf.size(), r.e - r.s - o);
            mach_vm_size_t got = 0;
            if (mach_vm_read_overwrite(g_task, r.s + o, tr, (vm_address_t)buf.data(), &got) != KERN_SUCCESS) continue;
            for (size_t i = 0; i + 8 <= (size_t)got; i += 8) {
                uint64_t v; memcpy(&v, buf.data() + i, 8);
                if (objs.count(v) && !seen.count(v)) {
                    seen.insert(v);
                    printf("    static 0x%llx -> obj 0x%llx  SID=0x%llu\n",
                           (unsigned long long)(r.s + o), (unsigned long long)v,
                           (unsigned long long)obj_sid[v]);
                    found++;
                }
            }
        }
    }
    printf("[+] %d static ptrs to valid BasePlayer objects\n", found);
    return 0;
}
