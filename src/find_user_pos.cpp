// =============================================================================
// find_user_pos.cpp — locate user's fixed position: scan around every SID
// occurrence for world-valid float triplets; the position that repeats most
// across occurrences is the user's position.
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
#include <string>

static task_t g_task;
static bool rmem(uint64_t a, void* b, size_t s) {
    vm_size_t got = 0;
    return vm_read_overwrite(g_task, (vm_address_t)a, s, (vm_address_t)b, &got) == KERN_SUCCESS && (size_t)got == s;
}

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

    // Pass 1: find all occurrences of the target SID
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

    // Pass 2: for each occurrence, scan +/-0x3000 for world-valid triplets
    const int WIN = 0x3000;
    std::map<std::string, int> pos_count; // "x,y,z" -> count
    std::map<std::string, std::pair<uint64_t, int>> pos_src; // "x,y,z" -> (sid_addr, rel_off)
    for (auto& h : hits) {
        uint64_t base = h > WIN ? h - WIN : 0;
        std::vector<uint8_t> b(WIN * 2);
        if (!rmem(base, b.data(), WIN * 2)) continue;
        for (int off = 0; off + 12 <= WIN * 2; off += 4) {
            float x, y, z; memcpy(&x, b.data() + off, 4); memcpy(&y, b.data() + off + 4, 4); memcpy(&z, b.data() + off + 8, 4);
            if (!std::isfinite(x) || !std::isfinite(y) || !std::isfinite(z)) continue;
            if (fabsf(x) > 4000 || fabsf(z) > 4000 || y < 5 || y > 900) continue;
            if (sqrtf(x * x + z * z) < 100.0f) continue;
            char key[64]; snprintf(key, sizeof(key), "%.1f,%.1f,%.1f", x, y, z);
            pos_count[key]++;
            if (pos_count[key] == 1) pos_src[key] = {h, (int)(base + off - h)};
        }
    }
    // report top positions
    std::vector<std::pair<int, std::string>> ranked;
    for (auto& kv : pos_count) ranked.push_back({kv.second, kv.first});
    std::sort(ranked.begin(), ranked.end(), [](auto& a, auto& b) { return a.first > b.first; });
    printf("\n[*] Top candidate positions (count = #SID occurrences with this pos nearby):\n");
    for (int i = 0; i < (int)ranked.size() && i < 15; i++) {
        auto& src = pos_src[ranked[i].second];
        printf("    %3dx  (%s)  near SID@0x%llx rel=0x%+x\n",
               ranked[i].first, ranked[i].second.c_str(),
               (unsigned long long)src.first, src.second);
    }
    return 0;
}
