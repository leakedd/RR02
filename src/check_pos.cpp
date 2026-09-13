// =============================================================================
// check_pos.cpp — decisive test: for each known player SID (fresh scan),
// read position @ obj+0x1168 (obj = sid_addr - 0x1b0). Same class => same offset.
// =============================================================================
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>
#include <map>

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

int main() {
    const uint64_t SIDS[] = {
        76561197983858939ULL, 76561197999138417ULL, 76561198027456808ULL, 76561198030926242ULL, 76561198062363451ULL,
        76561198137251052ULL, 76561198301877150ULL, 76561198683194576ULL, 76561198755627002ULL, 76561198767306908ULL,
        76561198794992153ULL, 76561198984296471ULL, 76561199067065153ULL, 76561199209642894ULL, 76561199232739722ULL,
        76561199355558150ULL, 76561199366803776ULL, 76561199772241226ULL, 76561199829570458ULL, 76561199875350346ULL,
    };
    const int NS = sizeof(SIDS) / 8;
    pid_t pids[8192]; int n = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    for (int i = 0; i < n / (int)sizeof(pid_t); i++) {
        if (!pids[i]) continue; char path[PROC_PIDPATHINFO_MAXSIZE] = {};
        if (proc_pidpath(pids[i], path, sizeof(path)) > 0 && strstr(path, "RustClient")) {
            task_for_pid(mach_task_self(), pids[i], &g_task);
            printf("[+] Rust PID=%d\n", pids[i]);
            break;
        }
    }
    if (!g_task) return 1;
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

    std::map<uint64_t, int> target;
    for (int i = 0; i < NS; i++) target[SIDS[i]] = i;
    std::vector<uint64_t> hits[NS];
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
                auto it = target.find(v);
                if (it != target.end()) {
                    int idx = it->second;
                    hits[idx].push_back(r.s + o + i);
                }
            }
        }
    }
    printf("[+] hits per SID:\n");
    int n_ok = 0, n_tot = 0;
    for (int i = 0; i < NS; i++) {
        printf("    SID %llu: %zu hits", (unsigned long long)SIDS[i], hits[i].size());
        int ok = 0; uint64_t ok_addr = 0; float ox = 0, oy = 0, oz = 0; int nv = 0;
        for (auto& h : hits[i]) {
            uint64_t obj = h - 0x1b0;
            if (r64(obj) != 0x10399bac0ULL) continue; // vtable BasePlayer filter
            nv++;
            float x = rf(obj + 0x1168), y = rf(obj + 0x1168 + 4), z = rf(obj + 0x1168 + 8);
            // strict: real terrain height, far from spawn origin
            if (std::isfinite(x) && std::isfinite(y) && std::isfinite(z) &&
                fabsf(x) < 4000 && fabsf(z) < 4000 && y > 1 && y < 900 && sqrtf(x*x + z*z) > 200) {
                ok++; ok_addr = obj; ox = x; oy = y; oz = z;
                break;
            }
        }
        if (ok) { n_ok++; printf("  -> POS @0x%llx+0x1168 = (%.1f, %.1f, %.1f) WORLD\n", (unsigned long long)ok_addr, ox, oy, oz); }
        else printf("  -> no world pos @+0x1168 (vtable objs: %d)\n", nv);
        n_tot++;
    }
    printf("[+] %d/%d players have world pos @ +0x1168\n", n_ok, n_tot);
    return 0;
}
