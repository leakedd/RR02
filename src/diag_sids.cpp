
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>
#include <unordered_map>
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
static uint64_t r64(uint64_t a) { uint64_t v=0; rmem(a,&v,8); return v; }
static uint64_t spac(uint64_t p){ return p & 0x0000FFFFFFFFFFFFULL; }
static bool vp(uint64_t p)      { uint64_t s=spac(p); return s > 0x10000ULL && s < 0x7FFFFFFFFFFFULL; }

struct Rg { uint64_t s, e; };
static std::vector<Rg> g_rw;
static void enum_rw() {
    g_rw.clear();
    mach_vm_address_t a = 0; mach_vm_size_t sz; vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt; mach_port_t obj;
    while (true) {
        cnt = VM_REGION_BASIC_INFO_COUNT_64;
        if (mach_vm_region(g_task, &a, &sz, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &cnt, &obj) != KERN_SUCCESS) break;
        if ((info.protection & VM_PROT_READ) && (info.protection & VM_PROT_WRITE)) g_rw.push_back({a, a+sz});
        a += sz;
    }
}
static pid_t find_rust() {
    pid_t pids[16384]; int n = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    for (int i = 0; i < n/(int)sizeof(pid_t); i++) {
        if (!pids[i]) continue;
        char path[PROC_PIDPATHINFO_MAXSIZE] = {};
        if (proc_pidpath(pids[i], path, sizeof(path)) > 0 && strstr(path, "RustClient")) return pids[i];
    }
    return -1;
}
static std::string klass_name(uint64_t obj) {
    uint64_t vt = spac(r64(obj));
    if (!vp(vt)) return "";
    uint64_t kl = spac(r64(vt));
    if (!vp(kl)) return "";
    uint64_t np = spac(r64(kl + 0x10));
    if (!vp(np)) return "";
    char buf[128] = {};
    if (!rmem(np, buf, 127)) return "";
    return std::string(buf);
}

int main() {
    pid_t pid = find_rust();
    if (pid < 0) { printf("no rust\n"); return 1; }
    if (task_for_pid(mach_task_self(), pid, &g_task) != KERN_SUCCESS) { printf("tfp fail\n"); return 1; }
    enum_rw();
    const uint64_t SMIN = 76561198000000000ULL, SMAX = 76561200000000000ULL;
    const size_t C = 4*1024*1024;
    std::vector<uint8_t> buf(C);
    // collect ALL sid occurrences
    std::vector<std::pair<uint64_t,int>> occ;  // (addr, sid)
    for (auto& r : g_rw) {
        uint64_t rs = r.e - r.s;
        if (rs > 512ULL*1024*1024) continue;
        for (uint64_t o = 0; o < rs; o += C) {
            uint64_t tr = std::min<uint64_t>(C, rs - o);
            mach_vm_size_t got = 0;
            if (mach_vm_read_overwrite(g_task, r.s+o, tr, (vm_address_t)buf.data(), &got) != KERN_SUCCESS) break;
            for (size_t i = 0; i+8 <= got; i += 8) {
                uint64_t v; memcpy(&v, buf.data()+i, 8);
                if (v >= SMIN && v < SMAX) occ.push_back({r.s+o+i, v});
            }
        }
    }
    printf("total SID occurrences: %zu\n", occ.size());
    // unique SIDs
    std::unordered_map<uint64_t,int> sid_count;
    for (auto& [a,v] : occ) sid_count[v]++;
    printf("unique SIDs: %zu\n", sid_count.size());
    for (auto& [s,c] : sid_count) printf("  SID=%llu x%d\n", (unsigned long long)s, c);
    // For each occurrence: try to find a "klass Player" object by scanning BACK from addr
    // Check obj candidates at addr - off for off in 0..0x1200 step 8. Count klass names.
    std::unordered_map<std::string,int> name_count;
    std::unordered_map<uint64_t,std::vector<uint64_t>> sid_objs;
    int nchk = 0;
    for (auto& [addr, sid] : occ) {
        if (nchk++ > 1200) break;
        for (int off = 0; off <= 0x1200; off += 8) {
            uint64_t obj = addr - off;
            if (!vp(obj)) continue;
            std::string kn = klass_name(obj);
            if (kn.empty()) continue;
            // quick reject: name must start with uppercase ascii
            if (kn[0] < 'A' || kn[0] > 'Z') continue;
            name_count[kn]++;
            if (kn.find("Player") != std::string::npos)
                sid_objs[sid].push_back(obj);
            break;  // only nearest klass-bearing object
        }
    }
    printf("\nklass names near SID addrs:\n");
    std::vector<std::pair<std::string,int>> nc(name_count.begin(), name_count.end());
    std::sort(nc.begin(), nc.end(), [](auto&a,auto&b){return a.second>b.second;});
    for (int i = 0; i < (int)nc.size() && i < 25; i++) printf("  %-30s x%d\n", nc[i].first.c_str(), nc[i].second);
    printf("\nPlayer-ish objects per SID:\n");
    for (auto& [s, objs] : sid_objs) {
        printf("  SID=%llu: %zu objects:", (unsigned long long)s, objs.size());
        for (int i = 0; i < (int)objs.size() && i < 4; i++) printf(" 0x%llx(+%s)", (unsigned long long)objs[i], klass_name(objs[i]).c_str());
        printf("\n");
    }
    // Also: for each unique SID, dump the OBJ layout where klass name is exactly "BasePlayer" if any
    return 0;
}
