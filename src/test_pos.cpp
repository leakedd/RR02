// ============================================================================
// RR02/test_pos.cpp — Test if positions change over time
// Vtable=0x1279db300, SID=+0x630, PM=+0x530, POS=PM+0x1E8
// Takes 2 snapshots 3s apart, reports deltas > 0.5m
// Compile: c++ -O2 -std=c++17 -o test_pos test_pos.cpp
// Run: echo PASSWORD | sudo -S ./test_pos
// ============================================================================

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>

static task_t g_task;
static bool read_mem(uint64_t addr, void* buf, size_t size) {
    vm_size_t got = 0;
    return vm_read_overwrite(g_task, addr, size, (vm_address_t)buf, &got) == KERN_SUCCESS && got == size;
}
static uint64_t r64(uint64_t a) { uint64_t v=0; read_mem(a,&v,8); return v; }
static float rf(uint64_t a) { float v=0; read_mem(a,&v,4); return v; }
static bool vptr(uint64_t p) { return p > 0x100000ULL && p < 0x800000000000ULL; }

static pid_t find_rust() {
    pid_t pids[4096]; int n = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    for (int i = 0; i < n / (int)sizeof(pid_t); i++) {
        char path[1024]; if (proc_pidpath(pids[i], path, sizeof(path)) > 0 && strstr(path, "RustClient")) return pids[i];
    }
    return -1;
}

static const uint64_t VTABLE = 0x1279db300;
static const int SID_OFFSET = 0x630;
static const int PM_OFFSET = 0x530;
static const int POS_OFFSET = 0x1E8;
static const uint64_t SID_MIN = 76561198000000000ULL;
static const uint64_t SID_MAX = 76561200000000000ULL;

struct Rg { uint64_t start, end; uint32_t prot; };

struct Player {
    uint64_t bp, sid, pm;
    float x[2], y[2], z[2];  // two snapshots
    bool ok;
};

int main() {
    printf("=== RR02 Test Pos (2 snapshots, 3s apart) ===\n");
    printf("Si tu lis ca, VA BOUGER EN JEU !\n\n");

    pid_t pid = find_rust();
    if (pid < 0) { printf("[!] Rust not found\n"); return 1; }
    if (task_for_pid(mach_task_self(), pid, &g_task) != KERN_SUCCESS) { printf("[!] t_f_p failed\n"); return 1; }

    std::vector<Rg> regions;
    mach_vm_address_t addr = 0; mach_vm_size_t sz; vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt; mach_port_t obj;
    while (true) {
        cnt = VM_REGION_BASIC_INFO_COUNT_64;
        if (mach_vm_region(g_task, &addr, &sz, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &cnt, &obj) != KERN_SUCCESS) break;
        if ((info.protection & VM_PROT_READ) && (info.protection & 2))
            regions.push_back({addr, addr + sz, (uint32_t)info.protection});
        addr += sz;
    }

    const size_t CHUNK = 8*1024*1024;
    static uint8_t buf[8*1024*1024];
    std::vector<Player> players;

    for (auto& rg : regions) {
        if (rg.end - rg.start > 256*1024*1024) continue;
        for (uint64_t off = 0; off < rg.end - rg.start; off += CHUNK) {
            uint64_t ch = std::min((uint64_t)CHUNK, rg.end - rg.start - off);
            mach_vm_size_t got = 0;
            if (mach_vm_read_overwrite(g_task, rg.start + off, ch, (vm_address_t)buf, &got) != KERN_SUCCESS) break;
            size_t n = got / 8;
            for (size_t i = 0; i < n; i++) {
                uint64_t v; memcpy(&v, buf+i*8, 8);
                if (v != VTABLE) continue;
                uint64_t bp = rg.start + off + i*8;
                uint64_t sid = r64(bp + SID_OFFSET);
                if (sid < SID_MIN || sid >= SID_MAX) continue;
                uint64_t pm = r64(bp + PM_OFFSET);
                if (!vptr(pm)) continue;

                // Check if we already tracked this SID
                bool dup = false;
                for (auto& p : players) { if (p.sid == sid) { dup = true; break; } }
                if (dup) continue;

                float px = rf(pm + POS_OFFSET);
                float py = rf(pm + POS_OFFSET + 4);
                float pz = rf(pm + POS_OFFSET + 8);
                if (!std::isfinite(px) || !std::isfinite(py) || !std::isfinite(pz)) continue;
                if (px < -5000 || px > 5000 || pz < -5000 || pz > 5000) continue;

                Player p{};
                p.bp = bp; p.sid = sid; p.pm = pm;
                p.x[0] = px; p.y[0] = py; p.z[0] = pz;
                p.ok = true;
                players.push_back(p);
            }
        }
    }

    printf("[+] Snapshot 1: %zu players with valid positions\n", players.size());

    // Wait 3 seconds
    printf("[*] Waiting 3s...\n");
    fflush(stdout);
    sleep(3);

    // Snapshot 2
    int changed = 0;
    for (auto& p : players) {
        p.x[1] = rf(p.pm + POS_OFFSET);
        p.y[1] = rf(p.pm + POS_OFFSET + 4);
        p.z[1] = rf(p.pm + POS_OFFSET + 8);

        float dx = p.x[1] - p.x[0];
        float dz = p.z[1] - p.z[0];
        float dist = sqrtf(dx*dx + dz*dz);

        if (dist > 0.5f) {
            changed++;
            printf("  MOVED! SID=%llu pos=(%.1f,%.1f)->(%.1f,%.1f) delta=%.1fm\n",
                   p.sid % 100000, p.x[0], p.z[0], p.x[1], p.z[1], dist);
        }
    }

    printf("[+] Snapshot 2: %d/%zu players moved (>0.5m)\n", changed, players.size());

    // Show all positions
    printf("\n=== All positions ===\n");
    printf("%-10s %-24s %-24s\n", "SID", "Snapshot 1", "Snapshot 2");
    for (auto& p : players) {
        printf("%-10llu (%.1f, %.1f, %.1f)  (%.1f, %.1f, %.1f)\n",
               p.sid % 100000, p.x[0], p.y[0], p.z[0], p.x[1], p.y[1], p.z[1]);
    }

    return 0;
}