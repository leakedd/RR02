// =============================================================================
// check_uc.cpp — re-scan user SID fresh, test UC offsets (build 24614784):
//   SID@0x718, playerModel@0x340->pos@0x2F8, cand pos @ SID+0xfb8
// =============================================================================
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>

static task_t g_task;
static bool rmem(uint64_t a, void* b, size_t s) {
    vm_size_t got = 0;
    return vm_read_overwrite(g_task, (vm_address_t)a, s, (vm_address_t)b, &got) == KERN_SUCCESS && (size_t)got == s;
}
static uint64_t r64(uint64_t a) { uint64_t v = 0; rmem(a, &v, 8); return v; }
static float rf(uint64_t a) { float v = 0; rmem(a, &v, 4); return v; }
static bool is_sid(uint64_t v) { return v >= 76561197960265728ULL && v < 76561202255233023ULL; }

struct Rg { uint64_t s, e; };
static std::vector<Rg> g_rw;

int main(int argc, char** argv) {
    uint64_t TARGET = argc > 1 ? strtoull(argv[1], NULL, 10) : 76561198984296471ULL;
    pid_t pids[8192]; int n = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    for (int i = 0; i < n / (int)sizeof(pid_t); i++) {
        if (!pids[i]) continue; char path[PROC_PIDPATHINFO_MAXSIZE] = {};
        if (proc_pidpath(pids[i], path, sizeof(path)) > 0 && strstr(path, "RustClient")) {
            task_for_pid(mach_task_self(), pids[i], &g_task);
            printf("[+] Rust PID=%d\n", pids[i]);
            break;
        }
    }
    if (!g_task) { printf("[!] not found\n"); return 1; }
    uint64_t a = 0; mach_vm_size_t sz = 0;
    while (1) {
        vm_region_basic_info_data_64_t info;
        mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t obj = 0;
        if (mach_vm_region(g_task, &a, &sz, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &cnt, &obj) != KERN_SUCCESS) break;
        if ((info.protection & VM_PROT_READ) && (info.protection & VM_PROT_WRITE)) g_rw.push_back({a, a + sz});
        a += sz;
    }
    printf("[+] %zu RW regions\n", g_rw.size());

    std::vector<uint64_t> hits;
    std::vector<uint8_t> buf(4 * 1024 * 1024);
    for (auto& r : g_rw) {
        uint64_t rs = r.e - r.s;
        if (rs > 512ULL * 1024 * 1024) continue;
        for (uint64_t o = 0; o < rs; o += buf.size()) {
            uint64_t tr = std::min((uint64_t)buf.size(), rs - o);
            mach_vm_size_t got = 0;
            if (mach_vm_read_overwrite(g_task, r.s + o, tr, (vm_address_t)buf.data(), &got) != KERN_SUCCESS) break;
            for (size_t i = 0; i + 8 <= (size_t)got; i += 8) {
                uint64_t v; memcpy(&v, buf.data() + i, 8);
                if (v == TARGET) hits.push_back(r.s + o + i);
            }
        }
    }
    printf("[+] %zu SID occurrences\n", hits.size());

    int n_bp = 0, n_cand = 0;
    for (auto& h : hits) {
        uint64_t obj = h - 0x1b0;
        uint64_t sid718 = r64(obj + 0x718);
        uint64_t pm = r64(obj + 0x340);
        float cx, cy, cz; rmem(h + 0xfb8, &cx, 4); rmem(h + 0xfb8 + 4, &cy, 4); rmem(h + 0xfb8 + 8, &cz, 4);
        float px = 0, py = 0, pz = 0;
        if (pm > 0x10000 && pm < 0x7FFFFFFFFFFFULL) rmem(pm + 0x2F8, &px, 4), rmem(pm + 0x2F8 + 4, &py, 4), rmem(pm + 0x2F8 + 8, &pz, 4);
        bool wc = std::isfinite(cx) && fabsf(cx) < 4000 && fabsf(cz) < 4000 && cy > -100 && cy < 1000;
        bool wp = std::isfinite(px) && fabsf(px) < 4000 && fabsf(pz) < 4000 && py > -100 && py < 1000;
        if (is_sid(sid718)) n_bp++;
        if (wc) n_cand++;
        printf("SID@0x%llx obj=0x%llx | SID718=%s | pm=0x%llx pos(pm+2F8)=(%.1f,%.1f,%.1f)%s | cand@+fb8=(%.1f,%.1f,%.1f)%s\n",
            (unsigned long long)h, (unsigned long long)obj,
            is_sid(sid718) ? "SID!!" : "-----",
            (unsigned long long)pm, px, py, pz, wp ? " WORLD" : "",
            cx, cy, cz, wc ? " WORLD" : "");
    }
    printf("[+] BasePlayer-like (SID@0x718): %d / %zu | world cand @+fb8: %d / %zu\n",
           n_bp, hits.size(), n_cand, hits.size());
    return 0;
}
