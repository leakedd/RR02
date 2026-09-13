// rescan.cpp — quick fresh scan: find local SID@+0x1b0, read position, compare 2s later
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>
#include <map>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#include <unistd.h>

static task_t g_task;
static bool rmem(uint64_t a, void* b, size_t s) {
    vm_size_t got = 0;
    return vm_read_overwrite(g_task, (vm_address_t)a, s, (vm_address_t)b, &got) == KERN_SUCCESS && (size_t)got == s;
}
static uint64_t r64(uint64_t a) { uint64_t v = 0; rmem(a, &v, 8); return v; }
static float rf(uint64_t a) { float v = 0; rmem(a, &v, 4); return v; }
static bool is_sid(uint64_t v) { return v >= 76561197960265728ULL && v <= 76561202255233023ULL; }

static pid_t find_rust() {
    pid_t pids[8192]; int n = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    for (int i = 0; i < n / (int)sizeof(pid_t); i++) {
        if (!pids[i]) continue; char path[PROC_PIDPATHINFO_MAXSIZE] = {};
        if (proc_pidpath(pids[i], path, sizeof(path)) > 0 && strstr(path, "RustClient")) return pids[i];
    }
    return -1;
}

struct Rg { uint64_t s, e; };
static std::vector<Rg> g_rw;

int main() {
    pid_t pid = find_rust();
    if (pid < 0) { printf("[!] Rust not running\n"); return 1; }
    printf("[+] Rust PID=%d\n", pid);
    if (task_for_pid(mach_task_self(), pid, &g_task) != KERN_SUCCESS) { printf("[!] tfp\n"); return 1; }

    // Enumerate RW regions
    mach_vm_address_t a = 0; mach_vm_size_t sz;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt; mach_port_t obj;
    while (true) {
        cnt = VM_REGION_BASIC_INFO_COUNT_64;
        if (mach_vm_region(g_task, &a, &sz, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &cnt, &obj) != KERN_SUCCESS) break;
        if ((info.protection & VM_PROT_READ) && (info.protection & VM_PROT_WRITE))
            g_rw.push_back({a, a + sz});
        a += sz;
    }
    printf("[+] %zu RW regions\n", g_rw.size());

    // Scan for all SIDs @+0x1b0 with valid position @+0x1168
    const int POS = 0x1168;
    const uint64_t LOCAL_SID = 76561198984296471ULL;
    std::map<uint64_t, uint64_t> players; // sid -> obj
    std::vector<uint8_t> buf(4*1024*1024);

    for (auto& r : g_rw) {
        uint64_t rs = r.e - r.s;
        if (rs > 512ULL*1024*1024) continue;
        for (uint64_t o = 0; o < rs; o += buf.size()) {
            uint64_t tr = std::min((uint64_t)buf.size(), rs - o);
            mach_vm_size_t got = 0;
            if (mach_vm_read_overwrite(g_task, r.s + o, tr, (vm_address_t)buf.data(), &got) != KERN_SUCCESS) continue;
            for (size_t i = 0; i + 8 <= (size_t)got; i += 8) {
                uint64_t v; memcpy(&v, buf.data()+i, 8);
                if (!is_sid(v)) continue;
                uint64_t obj_addr = r.s + o + i - 0x1b0;
                if (obj_addr < r.s) continue;
                float x = rf(obj_addr + POS), y = rf(obj_addr + POS + 4), z = rf(obj_addr + POS + 8);
                if (!std::isfinite(x) || !std::isfinite(y) || !std::isfinite(z)) continue;
                if (y < 0.5f || y > 2000.f) continue;
                if (x == 0.f && y == 1.f && z == 0.f) continue;
                if (x == 100.f && y == 100.f && z == 0.f) continue;
                if (x == 100.f && y == 100.f && z == 100.f) continue;
                if (x == 0.f && y == 1.f && z == 1.f) continue;
                if (x == 0.f && y == 1.f && z == -1.f) continue;
                if (sqrtf(x*x + z*z) < 30.f && y < 5.f) continue; // too close to origin
                if (!players.count(v)) players[v] = obj_addr;
            }
        }
    }

    printf("[+] %zu SIDs found\n", players.size());
    
    // Find local
    uint64_t local_obj = 0;
    for (auto& kv : players) if (kv.first == LOCAL_SID) { local_obj = kv.second; break; }
    if (!local_obj) printf("[!] LOCAL SID not found by scan, using fallback 0x68aaec980\n");
    else printf("[+] LOCAL: obj=0x%llx\n", (unsigned long long)local_obj);

    // Read positions NOW
    printf("\n--- Position snapshot ---\n");
    for (auto& kv : players) {
        float x=rf(kv.second+POS), y=rf(kv.second+POS+4), z=rf(kv.second+POS+8);
        const char* tag = (kv.first == LOCAL_SID) ? " *** LOCAL" : "";
        printf("  SID=%llu pos=(%.1f,%.1f,%.1f)%s\n", (unsigned long long)kv.first, x, y, z, tag);
    }

    // Re-read LOCAL after 2s
    uint64_t lo = local_obj ? local_obj : 0x68aaec980ULL;
    float lx1=rf(lo+POS), ly1=rf(lo+POS+4), lz1=rf(lo+POS+8);
    printf("\nLocal pos now: (%.2f,%.2f,%.2f)\n", lx1, ly1, lz1);
    sleep(2);
    float lx2=rf(lo+POS), ly2=rf(lo+POS+4), lz2=rf(lo+POS+8);
    float d = sqrtf((lx2-lx1)*(lx2-lx1)+(ly2-ly1)*(ly2-ly1)+(lz2-lz1)*(lz2-lz1));
    printf("Local pos +2s:  (%.2f,%.2f,%.2f)  delta=%.3f\n", lx2, ly2, lz2, d);
    if (d > 0.01f) printf("🔴 LOCAL MOVING (%.3f m in 2s)\n", d);
    else printf("local statique (AFK)\n");

    // Check a distant player too
    if (players.size() > 1) {
        auto it = players.begin();
        if (it->first == LOCAL_SID && players.size() > 1) ++it;
        uint64_t dobj = it->second;
        float dx1=rf(dobj+POS), dy1=rf(dobj+POS+4), dz1=rf(dobj+POS+8);
        sleep(2);
        float dx2=rf(dobj+POS), dy2=rf(dobj+POS+4), dz2=rf(dobj+POS+8);
        float dd = sqrtf((dx2-dx1)*(dx2-dx1)+(dy2-dy1)*(dy2-dy1)+(dz2-dz1)*(dz2-dz1));
        printf("Distant P[%llu] pos now: (%.2f,%.2f,%.2f)\n", (unsigned long long)it->first, dx1, dy1, dz1);
        printf("Distant P[%llu] pos +4s: (%.2f,%.2f,%.2f) delta=%.3f\n", (unsigned long long)it->first, dx2, dy2, dz2, dd);
        if (dd > 0.01f) printf("🔴 DISTANT MOVING (%.3f m)\n", dd);
        else printf("distant statique (AFK)\n");
    }

    return 0;
}
