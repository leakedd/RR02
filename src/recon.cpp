// ============================================================================
// RR02/recon.cpp — Memory reconnaissance for Rust (macOS ARM64)
// Finds: GameAssembly base, SteamIDs, BasePlayer candidates, offsets
// Compile: c++ -O2 -o recon recon.cpp
// Run: sudo ./recon
// ============================================================================

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>
#include <unordered_map>
#include <string>
#include <algorithm>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>

static task_t g_task;

static bool read_mem(uint64_t addr, void* buf, size_t size) {
    vm_size_t got = 0;
    return vm_read_overwrite(g_task, addr, size, (vm_address_t)buf, &got) == KERN_SUCCESS && got == size;
}

template<typename T> static T rm(uint64_t a) {
    T v{}; read_mem(a, &v, sizeof(v)); return v;
}

static uint64_t r64(uint64_t a) { return rm<uint64_t>(a); }
static uint32_t r32(uint64_t a) { return rm<uint32_t>(a); }
static float    rf (uint64_t a) { return rm<float>(a); }

static bool vptr(uint64_t p) { return p > 0x100000ULL && p < 0x800000000000ULL; }

static std::string read_il2cpp_str(uint64_t field_addr) {
    uint64_t str = r64(field_addr);
    if (!vptr(str)) return "";
    uint32_t len = r32(str + 0x10);
    if (len == 0 || len > 64) return "";
    std::string out;
    for (uint32_t i = 0; i < len && i < 63; i++) {
        uint16_t c = rm<uint16_t>(str + 0x14 + i * 2);
        if (c == 0) break;
        out += (c > 31 && c < 127) ? (char)c : '?';
    }
    return (out.size() >= 2) ? out : "";
}

static pid_t find_rust() {
    pid_t pids[4096];
    int n = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    for (int i = 0; i < n / (int)sizeof(pid_t); i++) {
        char path[1024];
        if (proc_pidpath(pids[i], path, sizeof(path)) > 0 && strstr(path, "RustClient"))
            return pids[i];
    }
    return -1;
}

struct Region { uint64_t start, end; uint32_t prot; uint64_t size() const { return end - start; } };

static std::vector<Region> get_regions() {
    std::vector<Region> regions;
    mach_vm_address_t addr = 0;
    mach_vm_size_t size;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt;
    mach_port_t obj;
    while (true) {
        cnt = VM_REGION_BASIC_INFO_COUNT_64;
        if (mach_vm_region(g_task, &addr, &size, VM_REGION_BASIC_INFO_64,
                           (vm_region_info_t)&info, &cnt, &obj) != KERN_SUCCESS) break;
        if (info.protection & VM_PROT_READ)
            regions.push_back({addr, addr + size, (uint32_t)info.protection});
        addr += size;
    }
    return regions;
}

static const uint64_t SID_MIN = 76561198000000000ULL;
static const uint64_t SID_MAX = 76561200000000000ULL;

struct PlayerCand {
    uint64_t bp_addr, sid, player_model;
    std::string name;
    float health;
    uint32_t flags;
};

static std::vector<PlayerCand> scan_for_players(const std::vector<Region>& regions) {
    printf("[*] Scanning %zu regions for SteamIDs...\n", regions.size());
    fflush(stdout);
    std::unordered_map<uint64_t, PlayerCand> by_sid;
    const size_t CHUNK = 8 * 1024 * 1024;
    static uint8_t buf[8 * 1024 * 1024];
    int ri = 0;
    for (auto& rg : regions) {
        ri++;
        if (rg.size() > 256 * 1024 * 1024) continue;
        if (!(rg.prot & 2)) continue;
        for (uint64_t off = 0; off < rg.size(); off += CHUNK) {
            uint64_t chunk = std::min((uint64_t)CHUNK, rg.size() - off);
            mach_vm_size_t got = 0;
            if (mach_vm_read_overwrite(g_task, rg.start + off, chunk,
                                       (vm_address_t)buf, &got) != KERN_SUCCESS) break;
            for (size_t i = 0; i + 8 <= got; i += 8) {
                uint64_t v; memcpy(&v, buf + i, 8);
                if (v < SID_MIN || v >= SID_MAX) continue;
                uint64_t sid_addr = rg.start + off + i;
                if (sid_addr < 0x700) continue;
                // Try SID at offset 0x6B8 from BasePlayer
                uint64_t bp = sid_addr - 0x6B8;
                uint64_t sid_check = rm<uint64_t>(bp + 0x6B8);
                if (sid_check != v) continue;
                uint64_t vtable = r64(bp);
                if (!vptr(vtable)) continue;
                // Try playerModel
                uint64_t pm = 0;
                for (uint32_t pm_off : {0x678u, 0x680u, 0x670u, 0x688u, 0x690u}) {
                    uint64_t cand = r64(bp + pm_off);
                    if (vptr(cand)) { pm = cand; break; }
                }
                // Try name
                std::string name;
                for (uint32_t nm_off : {0x488u, 0x490u, 0x480u, 0x498u, 0x4A0u}) {
                    name = read_il2cpp_str(bp + nm_off);
                    if (name.size() >= 2 && name.find(".prefab") == std::string::npos &&
                        name.find("UnityEngine") == std::string::npos) break;
                    name.clear();
                }
                float hp = -1;
                for (uint32_t hp_off : {0x29Cu, 0x2A0u, 0x298u, 0x2A4u}) {
                    float h = rf(bp + hp_off);
                    if (std::isfinite(h) && h >= 0 && h <= 200) { hp = h; break; }
                }
                uint32_t flags = r32(bp + 0x670);
                auto it = by_sid.find(v);
                if (it != by_sid.end()) {
                    if (pm && !it->second.player_model) {} 
                    else if (!pm && it->second.player_model) continue;
                }
                PlayerCand c{}; c.bp_addr = bp; c.sid = v; c.player_model = pm;
                c.name = name; c.health = hp; c.flags = flags;
                by_sid[v] = c;
            }
        }
        if (ri % 20 == 0) { printf("\r[*] Region %d/%zu, %zu candidates...", ri, regions.size(), by_sid.size()); fflush(stdout); }
    }
    printf("\r[*] Done. %zu unique players.\n", by_sid.size());
    std::vector<PlayerCand> result;
    for (auto& [sid, c] : by_sid) result.push_back(c);
    return result;
}

static void probe_position(uint64_t player_model) {
    if (!vptr(player_model)) return;
    struct Bone { uint32_t off; const char* name; };
    Bone bones[] = {{0x28,"root"},{0x30,"head"},{0x38,"eye"},{0x40,"spine"},{0x48,"hip"}};
    for (auto& b : bones) {
        uint64_t managed = r64(player_model + b.off);
        if (!vptr(managed)) continue;
        uint64_t native = r64(managed + 0x10);
        if (!vptr(native)) continue;
        for (int64_t s = -0x400; s <= 0x400; s += 4) {
            uint64_t a = (uint64_t)((int64_t)native + s);
            float x = rf(a), y = rf(a + 4), z = rf(a + 8);
            if (!std::isfinite(x) || !std::isfinite(y) || !std::isfinite(z)) continue;
            if (x < -5000 || x > 5000 || z < -5000 || z > 5000) continue;
            if (y < -200 || y > 2000) continue;
            float mag = sqrtf(x*x + z*z);
            if (mag < 10.0f) continue;
            printf("    [POS] bone=%s → (%.1f, %.1f, %.1f)\n", b.name, x, y, z);
            return;
        }
    }
    printf("    [POS] NOT FOUND\n");
}

int main() {
    printf("=== RR02 Recon ===\n");
    pid_t pid = find_rust();
    if (pid < 0) { printf("[!] Rust not found\n"); return 1; }
    printf("[+] Rust pid=%d\n", pid);
    if (task_for_pid(mach_task_self(), pid, &g_task) != KERN_SUCCESS) {
        printf("[!] task_for_pid failed (run with sudo)\n"); return 1;
    }
    printf("[+] task OK\n");
    auto regions = get_regions();
    printf("[+] %zu regions\n", regions.size());
    auto players = scan_for_players(regions);
    printf("\n=== PLAYERS ===\n");
    for (auto& p : players) {
        printf("  SID=%llu BP=0x%llx PM=0x%llx name=\"%s\" hp=%.0f flags=0x%x\n",
               p.sid, p.bp_addr, p.player_model, p.name.c_str(), p.health, p.flags);
        if (p.player_model) probe_position(p.player_model);
    }
    printf("\n  Total: %zu | WithPM: %zu | Named: %zu\n", players.size(),
        std::count_if(players.begin(), players.end(), [](auto& c){ return c.player_model; }),
        std::count_if(players.begin(), players.end(), [](auto& c){ return !c.name.empty(); }));
    return 0;
}