// =============================================================================
// vtable_check.cpp — Check if the known BasePlayer runtime vtable (0x141dcf380)
// is still valid in the current game build, and count objects matching it.
// =============================================================================
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <algorithm>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>

static task_t g_task;
static bool rmem(uint64_t a, void* b, size_t s) {
    vm_size_t got = 0;
    return vm_read_overwrite(g_task, (vm_address_t)a, s, (vm_address_t)b, &got) == KERN_SUCCESS && (size_t)got == s;
}
static uint64_t r64(uint64_t a) { uint64_t v = 0; rmem(a, &v, 8); return v; }
static uint64_t spac(uint64_t p) { return p & 0x0000FFFFFFFFFFFFULL; }
static bool vp(uint64_t p) { uint64_t s = spac(p); return s > 0x10000ULL && s < 0x7FFFFFFFFFFFULL; }

static pid_t find_rust() {
    pid_t pids[8192]; int n = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    for (int i = 0; i < n / (int)sizeof(pid_t); i++) {
        if (!pids[i]) continue; char path[PROC_PIDPATHINFO_MAXSIZE] = {};
        if (proc_pidpath(pids[i], path, sizeof(path)) > 0 && strstr(path, "Rust")) return pids[i];
    }
    return -1;
}

struct Rg { uint64_t s, e; };
static std::vector<Rg> g_rw;
static void enum_rg() {
    mach_vm_address_t a = 0; mach_vm_size_t sz; vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt; mach_port_t obj;
    while (true) {
        cnt = VM_REGION_BASIC_INFO_COUNT_64;
        if (mach_vm_region(g_task, &a, &sz, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &cnt, &obj) != KERN_SUCCESS) break;
        if ((info.protection & VM_PROT_READ) && (info.protection & VM_PROT_WRITE)) g_rw.push_back({a, a + sz});
        a += sz;
    }
}

int main() {
    pid_t pid = find_rust();
    if (pid < 0) { printf("[!] Rust not found\n"); return 1; }
    printf("[+] Rust PID=%d\n", pid);
    if (task_for_pid(mach_task_self(), pid, &g_task) != KERN_SUCCESS) { printf("[!] task_for_pid failed\n"); return 1; }
    enum_rg();
    printf("[+] %zu RW regions\n", g_rw.size());

    // Known vtable from 29/07 analysis
    const uint64_t VT[] = { 0x141dcf380ULL };
    const char* VT_NAME[] = { "BasePlayer" };

    // Count objects whose +0x00 == VT
    const size_t C = 4 * 1024 * 1024;
    std::vector<uint8_t> buf(C);
    for (size_t vi = 0; vi < sizeof(VT)/sizeof(VT[0]); vi++) {
        uint64_t vt = VT[vi];
        uint64_t count = 0;
        std::vector<uint64_t> sample;
        for (auto& r : g_rw) {
            uint64_t rs = r.e - r.s;
            if (rs > 512ULL * 1024 * 1024) continue;
            for (uint64_t o = 0; o < rs; o += C) {
                uint64_t tr = std::min((uint64_t)C, rs - o);
                mach_vm_size_t got = 0;
                if (mach_vm_read_overwrite(g_task, r.s + o, tr, (vm_address_t)buf.data(), &got) != KERN_SUCCESS) break;
                for (size_t i = 0; i + 8 <= (size_t)got; i += 8) {
                    uint64_t v; memcpy(&v, buf.data() + i, 8);
                    if (v == vt) {
                        uint64_t obj = r.s + o + i;
                        if (vp(obj + 0x10)) { count++; if (sample.size() < 5) sample.push_back(obj); }
                    }
                }
            }
        }
        printf("[%s] vtable 0x%llx -> %llu objects with valid +0x10\n", VT_NAME[vi], vt, count);
        for (auto a : sample) {
            uint64_t sid = 0;
            for (int off = 0x100; off < 0x900; off += 8) {
                uint64_t v = r64(a + off);
                if (v >= 76561198000000000ULL && v < 76561200000000000ULL) { sid = v; printf("    obj=0x%llx SID=%llu at +0x%x\n", a, v, off); break; }
            }
            if (!sid) printf("    obj=0x%llx (no SID in +0x100..0x900)\n", a);
        }
    }
    return 0;
}
