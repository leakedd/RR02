// ============================================================================
// RR02/radar.cpp — Radar temps réel pour Rust (macOS ARM64, 100% externe)
//
// Vtable: 0x141dcf380 (runtime BasePlayer vtable, ARM64)
// SteamID: +0x130
// Name: +0x660 (best guess)
// Health: +0x020 (28 for all? - health is at a different offset)
// PlayerModel: +0x530 → bone+0x28 → m_CachedPtr+0x10 → native → scan ±0x400 → Vec3
//
// Compile: c++ -O2 -std=c++17 -o radar radar.cpp
// Run: echo PASSWORD | sudo -S ./radar
// ============================================================================

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <algorithm>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>

// ============================================================================
// Config — resolved from find_vtable + resolve_offsets
// ============================================================================
static const uint64_t VTABLE       = 0x141dcf380;
static const int       SID_OFFSET   = 0x130;
static const int       NAME_OFFSET  = 0x660;  // best guess, may need tuning
static const int       PM_OFFSET    = 0x530;  // PlayerModel pointer
// Health offset TBD — +0x20 gives 28 for all, might be max health
// Flags offset TBD

static const uint64_t SID_MIN = 76561198000000000ULL;
static const uint64_t SID_MAX = 76561200000000000ULL;
static const char* JSON_PATH = "/Users/mac/Desktop/RR02/radar_data.json";

// ============================================================================
// Memory
// ============================================================================
static task_t g_task;
static bool read_mem(uint64_t addr, void* buf, size_t size) {
    vm_size_t got = 0;
    return vm_read_overwrite(g_task, addr, size, (vm_address_t)buf, &got) == KERN_SUCCESS && got == size;
}
template<typename T> static T rm(uint64_t a) { T v{}; read_mem(a, &v, sizeof(v)); return v; }
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
    bool in_tag = false;
    for (uint32_t i = 0; i < len && i < 63; i++) {
        uint16_t c = rm<uint16_t>(str + 0x14 + i * 2);
        if (c == 0) break;
        if (c == '<') { in_tag = true; continue; }
        if (c == '>') { in_tag = false; continue; }
        if (in_tag) continue;
        out += (c > 31 && c < 127) ? (char)c : '?';
    }
    return out;
}

static pid_t find_rust() {
    pid_t pids[4096]; int n = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    for (int i = 0; i < n / (int)sizeof(pid_t); i++) {
        char path[1024]; if (proc_pidpath(pids[i], path, sizeof(path)) > 0 && strstr(path, "RustClient")) return pids[i];
    }
    return -1;
}

struct Rg { uint64_t start, end; uint32_t prot; };
static std::vector<Rg> g_regions;

// ============================================================================
// Read position from PlayerModel → bone transform → native → scan for Vec3
// ============================================================================
static bool read_pos(uint64_t bp, float& ox, float& oy, float& oz) {
    uint64_t pm = r64(bp + PM_OFFSET);
    if (!vptr(pm)) return false;

    // Try each bone offset in PlayerModel
    for (uint32_t bo : {0x28u, 0x38u, 0x30u, 0x40u, 0x48u}) {
        uint64_t managed = r64(pm + bo);
        if (!vptr(managed)) continue;
        uint64_t native = r64(managed + 0x10);  // m_CachedPtr
        if (!vptr(native)) continue;

        // Scan around native for valid world coordinates
        float best_pos[3] = {0, 0, 0};
        bool found = false;
        float best_mag = 0;

        for (int64_t s = -0x400; s <= 0x400; s += 4) {
            uint64_t a = (uint64_t)((int64_t)native + s);
            float x = rf(a), y = rf(a + 4), z = rf(a + 8);
            if (!std::isfinite(x) || !std::isfinite(y) || !std::isfinite(z)) continue;
            if (x < -5000 || x > 5000 || z < -5000 || z > 5000) continue;
            if (y < -200 || y > 2000) continue;
            float mag = sqrtf(x*x + z*z);
            if (mag < 10.0f) continue;
            // Prefer the position with highest magnitude (likely the actual world pos)
            if (mag > best_mag) {
                best_mag = mag;
                best_pos[0] = x; best_pos[1] = y; best_pos[2] = z;
                found = true;
            }
        }
        if (found) {
            ox = best_pos[0]; oy = best_pos[1]; oz = best_pos[2];
            return true;
        }
    }
    return false;
}

// ============================================================================
// Player data
// ============================================================================
struct Player {
    uint64_t addr, sid;
    std::string name;
    float x, y, z;
    float health;
    bool is_me;
};

// ============================================================================
// Scan for BasePlayer objects
// ============================================================================
static std::vector<uint64_t> scan_objects() {
    std::vector<uint64_t> objects;
    const size_t CHUNK = 8 * 1024 * 1024;
    static uint8_t buf[8 * 1024 * 1024];

    for (auto& rg : g_regions) {
        if (rg.end - rg.start > 256 * 1024 * 1024) continue;
        for (uint64_t off = 0; off < rg.end - rg.start; off += CHUNK) {
            uint64_t ch = std::min((uint64_t)CHUNK, rg.end - rg.start - off);
            mach_vm_size_t got = 0;
            if (mach_vm_read_overwrite(g_task, rg.start + off, ch, (vm_address_t)buf, &got) != KERN_SUCCESS) break;
            size_t n = got / 8;
            for (size_t i = 0; i < n; i++) {
                uint64_t v; memcpy(&v, buf + i * 8, 8);
                if (v == VTABLE) {
                    uint64_t obj = rg.start + off + i * 8;
                    // Verify SID
                    uint64_t sid = r64(obj + SID_OFFSET);
                    if (sid >= SID_MIN && sid < SID_MAX) {
                        objects.push_back(obj);
                    }
                }
            }
        }
    }
    return objects;
}

// ============================================================================
// Extract unique players
// ============================================================================
static std::vector<Player> extract_players(const std::vector<uint64_t>& objects) {
    std::unordered_map<uint64_t, Player> by_sid;
    for (auto obj : objects) {
        uint64_t sid = r64(obj + SID_OFFSET);
        if (sid < SID_MIN || sid >= SID_MAX) continue;

        // Keep first occurrence per SID
        if (by_sid.count(sid)) continue;

        Player p{};
        p.addr = obj; p.sid = sid;
        p.x = p.y = p.z = 0; p.health = -1; p.is_me = false;

        std::string name = read_il2cpp_str(obj + NAME_OFFSET);
        if (!name.empty()) p.name = name;
        else p.name = "Player" + std::to_string(sid % 10000);

        read_pos(obj, p.x, p.y, p.z);
        by_sid[sid] = p;
    }

    std::vector<Player> result;
    for (auto& [sid, p] : by_sid) result.push_back(p);
    return result;
}

// ============================================================================
// Write JSON
// ============================================================================
static void write_json(const std::vector<Player>& players, float my_x, float my_y, float my_z, const std::string& my_name) {
    FILE* f = fopen(JSON_PATH, "w");
    if (!f) return;
    fprintf(f, "{\n  \"local\": {\"x\": %.2f, \"y\": %.2f, \"z\": %.2f, \"name\": \"%s\"},\n  \"players\": [\n",
            my_x, my_y, my_z, my_name.c_str());
    bool first = true;
    for (size_t i = 0; i < players.size(); i++) {
        auto& p = players[i];
        if (p.is_me) continue;
        float dist = sqrtf((p.x - my_x) * (p.x - my_x) + (p.z - my_z) * (p.z - my_z));
        if (!first) fprintf(f, ",\n");
        first = false;
        fprintf(f, "    {\"name\":\"%s\",\"x\":%.2f,\"y\":%.2f,\"z\":%.2f,\"dist\":%.1f,\"sid\":%llu}",
                p.name.c_str(), p.x, p.y, p.z, dist, p.sid);
    }
    fprintf(f, "\n  ]\n}\n");
    fclose(f);
}

// ============================================================================
// MAIN
// ============================================================================
int main() {
    printf("=== RR02 Radar ===\n");
    pid_t pid = find_rust();
    if (pid < 0) { printf("[!] Rust not found\n"); return 1; }
    printf("[+] Rust pid=%d\n", pid);
    if (task_for_pid(mach_task_self(), pid, &g_task) != KERN_SUCCESS) {
        printf("[!] task_for_pid failed (need sudo)\n"); return 1;
    }

    // Get writable regions (heap)
    mach_vm_address_t addr = 0; mach_vm_size_t sz; vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt; mach_port_t obj;
    while (true) {
        cnt = VM_REGION_BASIC_INFO_COUNT_64;
        if (mach_vm_region(g_task, &addr, &sz, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &cnt, &obj) != KERN_SUCCESS) break;
        if ((info.protection & VM_PROT_READ) && (info.protection & 2))
            g_regions.push_back({addr, addr + sz, (uint32_t)info.protection});
        addr += sz;
    }
    printf("[+] %zu writable regions\n", g_regions.size());

    // Initial scan
    printf("[*] Initial scan...\n");
    auto objects = scan_objects();
    printf("[+] %zu BasePlayer objects\n", objects.size());

    auto players = extract_players(objects);
    printf("[+] %zu unique players\n", players.size());

    for (auto& p : players) {
        printf("  SID=%llu name=\"%s\" pos=(%.1f, %.1f, %.1f)\n",
               p.sid, p.name.c_str(), p.x, p.y, p.z);
    }

    // Find local player (the one with the most "real" position)
    uint64_t my_sid = 0;
    float my_x = 0, my_y = 0, my_z = 0;
    std::string my_name = "ME";

    // Pick player with highest position magnitude (probably active and moving)
    float best_mag = 0;
    for (auto& p : players) {
        float mag = sqrtf(p.x * p.x + p.z * p.z);
        if (mag > best_mag) {
            best_mag = mag;
            my_sid = p.sid; my_x = p.x; my_y = p.y; my_z = p.z; my_name = p.name;
        }
    }
    // Mark me
    for (auto& p : players) if (p.sid == my_sid) p.is_me = true;

    printf("\n[+] Local player: SID=%llu name=\"%s\" pos=(%.1f, %.1f, %.1f)\n",
           my_sid, my_name.c_str(), my_x, my_y, my_z);

    // Radar loop
    printf("[*] Radar running. JSON → %s\n", JSON_PATH);
    printf("[*] Press Ctrl+C to stop.\n\n");

    uint64_t my_addr = 0;
    for (auto& p : players) if (p.sid == my_sid) my_addr = p.addr;

    int tick = 0;
    while (true) {
        tick++;

        // Update all player positions
        for (auto& p : players) {
            float fx, fy, fz;
            if (read_pos(p.addr, fx, fy, fz)) {
                p.x = fx; p.y = fy; p.z = fz;
            }
        }

        // Update local player
        if (my_addr) {
            float fx, fy, fz;
            if (read_pos(my_addr, fx, fy, fz)) { my_x = fx; my_y = fy; my_z = fz; }
        }

        // Write JSON
        write_json(players, my_x, my_y, my_z, my_name);

        // Rescan every 120 ticks (~12 seconds)
        if (tick % 120 == 0) {
            auto fresh_objects = scan_objects();
            std::unordered_set<uint64_t> fresh_sids;
            for (auto obj : fresh_objects) {
                uint64_t sid = r64(obj + SID_OFFSET);
                if (sid < SID_MIN || sid >= SID_MAX) continue;
                fresh_sids.insert(sid);

                bool found = false;
                for (auto& p : players) {
                    if (p.sid == sid) { p.addr = obj; found = true; break; }
                }
                if (!found) {
                    Player p{};
                    p.addr = obj; p.sid = sid; p.x = p.y = p.z = 0; p.health = -1; p.is_me = false;
                    std::string name = read_il2cpp_str(obj + NAME_OFFSET);
                    p.name = name.empty() ? "Player" + std::to_string(sid % 10000) : name;
                    read_pos(obj, p.x, p.y, p.z);
                    if (sid == my_sid) { p.is_me = true; my_addr = obj; }
                    players.push_back(p);
                }
            }
            // Remove disconnected players
            players.erase(std::remove_if(players.begin(), players.end(),
                [&](const Player& p) { return !p.is_me && !fresh_sids.count(p.sid); }), players.end());
        }

        // Console output
        int visible = 0;
        for (auto& p : players) {
            if (p.is_me) continue;
            float dist = sqrtf((p.x - my_x) * (p.x - my_x) + (p.z - my_z) * (p.z - my_z));
            if (dist < 500) visible++;
        }
        printf("\r[ME %.1f,%.1f,%.1f] %zu players (%d within 500m)     ",
               my_x, my_y, my_z, players.size(), visible);
        fflush(stdout);
        usleep(100000);  // 10 FPS
    }

    return 0;
}