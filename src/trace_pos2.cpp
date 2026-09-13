// =============================================================================
// trace_pos2.cpp — Refined: find REAL BasePlayer objects (not items/deployables)
//
// Problem: trace_pos v1 found items (Furnace, Sleeping Bag, etc.) instead of
// real players. The SteamID at +0x20 in items is actually the ownerID field.
//
// This version:
// 1. Scans for SteamIDs as before
// 2. For each SID hit, checks MULTIPLE vtable candidates
// 3. Identifies the real BasePlayer by filtering for objects with:
//    - A valid name that looks like a player name (not an item name)
//    - OR a unique vtable different from the item/deployable vtable
// 4. Groups objects by vtable and lets us see all distinct types
// 5. Deep walks the real BasePlayer objects for position
//
// Compile: c++ -O2 -std=c++17 -o trace_pos2 trace_pos2.cpp
// Run:     sudo ./trace_pos2
// =============================================================================

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <tuple>
#include <algorithm>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>

static task_t g_task;

static bool rmem(uint64_t addr, void* buf, size_t size) {
    vm_size_t got = 0;
    return vm_read_overwrite(g_task, (vm_address_t)addr, size,
                             (vm_address_t)buf, &got) == KERN_SUCCESS && (size_t)got == size;
}
static uint64_t r64(uint64_t a) { uint64_t v = 0; rmem(a, &v, 8); return v; }
static float    rf(uint64_t a)  { float v = 0;    rmem(a, &v, 4); return v; }
static uint64_t strip_pac(uint64_t p) { return p & 0x0000FFFFFFFFFFFFULL; }
static bool vptr(uint64_t p) {
    uint64_t s = strip_pac(p);
    return s > 0x10000ULL && s < 0x7FFFFFFFFFFFULL;
}

static pid_t find_rust() {
    pid_t pids[8192];
    int n = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    for (int i = 0; i < n / (int)sizeof(pid_t); i++) {
        if (pids[i] == 0) continue;
        char path[PROC_PIDPATHINFO_MAXSIZE] = {};
        if (proc_pidpath(pids[i], path, sizeof(path)) > 0)
            if (strstr(path, "Rust")) return pids[i];
    }
    return -1;
}

struct Region { uint64_t start, end; };
static std::vector<Region> g_rw;

static void enum_regions() {
    mach_vm_address_t addr = 0; mach_vm_size_t sz;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt; mach_port_t obj;
    while (true) {
        cnt = VM_REGION_BASIC_INFO_COUNT_64;
        if (mach_vm_region(g_task, &addr, &sz, VM_REGION_BASIC_INFO_64,
                           (vm_region_info_t)&info, &cnt, &obj) != KERN_SUCCESS) break;
        if ((info.protection & VM_PROT_READ) && (info.protection & VM_PROT_WRITE))
            g_rw.push_back({addr, addr + sz});
        addr += sz;
    }
}

static const uint64_t SID_MIN = 76561198000000000ULL;
static const uint64_t SID_MAX = 76561200000000000ULL;

struct SidHit { uint64_t addr, sid; };

static std::vector<SidHit> scan_sids() {
    std::vector<SidHit> hits;
    const size_t CHUNK = 4 * 1024 * 1024;
    std::vector<uint8_t> buf(CHUNK);
    for (auto& rg : g_rw) {
        uint64_t rsz = rg.end - rg.start;
        if (rsz > 512ULL * 1024 * 1024) continue;
        for (uint64_t off = 0; off < rsz; off += CHUNK) {
            uint64_t toread = std::min((uint64_t)CHUNK, rsz - off);
            mach_vm_size_t got = 0;
            if (mach_vm_read_overwrite(g_task, rg.start + off, toread,
                                        (vm_address_t)buf.data(), &got) != KERN_SUCCESS) break;
            for (size_t i = 0; i + 8 <= (size_t)got; i += 8) {
                uint64_t v;
                memcpy(&v, buf.data() + i, 8);
                if (v >= SID_MIN && v < SID_MAX) hits.push_back({rg.start + off + i, v});
            }
        }
    }
    return hits;
}

// IL2CPP string read
static std::string read_str(uint64_t ptr_addr) {
    uint64_t str = strip_pac(r64(ptr_addr));
    if (!vptr(str)) return "";
    uint32_t len = 0; rmem(str + 0x10, &len, 4);
    if (len == 0 || len > 64) return "";
    std::string out;
    for (uint32_t i = 0; i < len && i < 63; i++) {
        uint16_t c = 0; rmem(str + 0x14 + i * 2, &c, 2);
        if (c == 0) break;
        if (c >= 32 && c < 127) out += (char)c;
    }
    return out.size() >= 1 ? out : "";
}

// Known item/entity names to EXCLUDE (these are deployables, not players)
static bool is_item_name(const std::string& name) {
    static const char* items[] = {
        "Sleeping Bag", "Furnace", "Door", "Box", "Bag", "Bow", "AK47",
        "Thompson", "Hoodie", "Pants", "Rock", "Gloves", "Boots", "Wall",
        "Foundation", "Floor", "Ceiling", "Barricade", "Wheel", "Campfire",
        "Chest", "Tool", "Lock", "Key", "Sign", "Lantern", "Workbench",
        "Shotgun", "Pistol", "Rifle", "Revolver", "Salvaged", "Sheet Metal",
        "Armored", "Wooden", "Garage", "Wood Storage", "Large Wood",
        "Small Stash", "Spinning", "Research", "Repair", "Hunting",
        "Leather", "Bone", "Hide", "Cloth", "Tarp", "Sewing",
        NULL
    };
    for (int i = 0; items[i]; i++) {
        if (name.find(items[i]) != std::string::npos) return true;
    }
    return false;
}

// Position validity check
static bool is_world_pos(float x, float y, float z) {
    if (!std::isfinite(x) || !std::isfinite(y) || !std::isfinite(z)) return false;
    if (x < -5000 || x > 5000 || z < -5000 || z > 5000) return false;
    if (y < -500 || y > 3000) return false;
    return sqrtf(x*x + z*z) > 15.0f;
}

// Path through pointer chain
struct Path {
    int off[4];
    bool operator<(const Path& o) const {
        for (int i = 0; i < 4; i++) {
            if (off[i] != o.off[i]) return off[i] < o.off[i];
        }
        return false;
    }
};

struct PosEntry { Path path; float x, y, z; };

// Scan buffer for float triplets that look like world coords
static void scan_buf(const uint8_t* buf, int len,
                     int o1, int o2, int o3, std::vector<PosEntry>& out) {
    for (int fo = 0; fo + 12 <= len; fo += 4) {
        float x, y, z;
        memcpy(&x, buf + fo, 4);
        memcpy(&y, buf + fo + 4, 4);
        memcpy(&z, buf + fo + 8, 4);
        if (!is_world_pos(x, y, z)) continue;
        Path p;
        if (o2 == -99)      p = {fo, -1, -1, -1};           // Level 0
        else if (o3 == -99) p = {o1, fo, -1, -1};           // Level 1
        else if (o3 == -98) p = {o1, o2, fo, -1};           // Level 2
        else                p = {o1, o2, o3, fo};           // Level 3
        out.push_back({p, x, y, z});
    }
}

// Deep walk: 4 levels from a base address
static std::vector<PosEntry> snapshot(uint64_t base, int obj_size) {
    std::vector<PosEntry> res;
    std::vector<uint8_t> buf0(obj_size);
    if (!rmem(base, buf0.data(), obj_size)) return res;

    scan_buf(buf0.data(), obj_size, 0, -99, -99, res);

    std::unordered_set<uint64_t> v1;
    for (int o1 = 0; o1 + 8 <= obj_size; o1 += 8) {
        uint64_t p1; memcpy(&p1, buf0.data() + o1, 8);
        p1 = strip_pac(p1);
        if (!vptr(p1) || v1.count(p1)) continue;
        v1.insert(p1);

        uint8_t b1[0x500];
        if (!rmem(p1, b1, 0x500)) continue;
        scan_buf(b1, 0x500, o1, -99, -99, res);

        std::unordered_set<uint64_t> v2;
        for (int o2 = 0; o2 + 8 <= 0x200; o2 += 8) {
            uint64_t p2; memcpy(&p2, b1 + o2, 8);
            p2 = strip_pac(p2);
            if (!vptr(p2) || v2.count(p2)) continue;
            v2.insert(p2);

            uint8_t b2[0x400];
            if (!rmem(p2, b2, 0x400)) continue;
            scan_buf(b2, 0x400, o1, o2, -98, res);

            for (int o3 = 0; o3 + 8 <= 0x100; o3 += 8) {
                uint64_t p3; memcpy(&p3, b2 + o3, 8);
                p3 = strip_pac(p3);
                if (!vptr(p3)) continue;

                uint8_t b3[0x400];
                if (!rmem(p3, b3, 0x400)) continue;
                scan_buf(b3, 0x400, o1, o2, o3, res);
            }
        }
    }
    return res;
}

int main() {
    printf("\n  ╔═══════════════════════════════════════════════╗\n");
    printf("  ║  TRACE_POS v2 — Real BasePlayer Finder         ║\n");
    printf("  ╚═══════════════════════════════════════════════╝\n\n");

    pid_t pid = find_rust();
    if (pid < 0) { printf("[!] Rust not found\n"); return 1; }
    printf("[+] Rust PID=%d\n", pid);
    if (task_for_pid(mach_task_self(), pid, &g_task) != KERN_SUCCESS) {
        printf("[!] task_for_pid failed (sudo?)\n"); return 1;
    }
    enum_regions();
    printf("[+] %zu RW regions\n", g_rw.size());

    printf("[*] Scanning SteamIDs...\n");
    auto hits = scan_sids();
    printf("[+] %zu SID hits\n", hits.size());

    // Group by unique SID
    std::unordered_map<uint64_t, std::vector<uint64_t>> sid_locs;
    for (auto& h : hits) sid_locs[h.sid].push_back(h.addr);
    printf("[+] %zu unique SIDs\n\n", sid_locs.size());

    // =========================================================================
    // NEW: Try ALL vtable+offset combos and show the TOP groups with their names
    // =========================================================================
    struct VtGroup {
        uint64_t vtable;
        int sid_off;
        int count;
    };
    std::vector<VtGroup> groups;

    // Collect all (vtable, sid_offset) pairs
    std::map<std::pair<uint64_t, int>, int> vt_map;
    for (int soff = 0x10; soff <= 0xA00; soff += 0x08) {
        for (auto& [sid, addrs] : sid_locs) {
            uint64_t base = addrs[0] - soff;
            uint64_t vt = strip_pac(r64(base));
            if (vptr(vt)) vt_map[{vt, soff}]++;
        }
    }

    // Sort by count
    for (auto& [key, cnt] : vt_map) {
        if (cnt >= 3) groups.push_back({key.first, key.second, cnt});
    }
    std::sort(groups.begin(), groups.end(), [](auto& a, auto& b) { return a.count > b.count; });

    printf("=== Top Vtable Groups (>= 3 objects) ===\n");
    printf("%-18s %-10s %-6s  Sample Names\n", "Vtable", "SID_Off", "Count");
    printf("─────────────────────────────────────────────────────────\n");

    // For each group, show sample names
    int group_limit = std::min((int)groups.size(), 15);
    for (int g = 0; g < group_limit; g++) {
        auto& grp = groups[g];
        // Find sample objects
        std::vector<std::string> sample_names;
        int samples = 0;
        for (auto& [sid, addrs] : sid_locs) {
            if (samples >= 3) break;
            uint64_t base = addrs[0] - grp.sid_off;
            uint64_t vt = strip_pac(r64(base));
            if (vt == grp.vtable) {
                // Try reading name at several offsets
                for (int noff : {0x18, 0x20, 0x28, 0x2B0, 0x2B8, 0x2D0, 0x2D8, 0x660, 0x690}) {
                    std::string nm = read_str(base + noff);
                    if (!nm.empty() && nm.size() >= 2) {
                        sample_names.push_back(nm);
                        break;
                    }
                }
                samples++;
            }
        }
        printf("0x%llx  +0x%-5x %3d    ", grp.vtable, grp.sid_off, grp.count);
        for (size_t i = 0; i < sample_names.size(); i++) {
            if (i > 0) printf(", ");
            printf("\"%s\"", sample_names[i].c_str());
        }
        printf("\n");
    }

    // =========================================================================
    // Ask which group to use, or auto-detect player group
    // =========================================================================
    printf("\n[*] Auto-detecting player group...\n");

    // Strategy: the BasePlayer group should have objects where the "name"
    // is NOT a known item name. Also BasePlayer objects typically have
    // a valid m_CachedPtr at +0x10 from the managed object.
    //
    // Heuristic: for each group, count how many have non-item names
    int best_group = -1;
    int best_player_names = 0;

    for (int g = 0; g < group_limit; g++) {
        auto& grp = groups[g];
        int player_names = 0;
        int checked = 0;
        for (auto& [sid, addrs] : sid_locs) {
            if (checked >= 20) break;
            uint64_t base = addrs[0] - grp.sid_off;
            uint64_t vt = strip_pac(r64(base));
            if (vt != grp.vtable) continue;
            checked++;

            // Try reading name
            for (int noff : {0x18, 0x20, 0x28, 0x2B0, 0x2B8, 0x2D0, 0x2D8, 0x660, 0x690}) {
                std::string nm = read_str(base + noff);
                if (!nm.empty() && nm.size() >= 2) {
                    if (!is_item_name(nm)) {
                        player_names++;
                    }
                    break;
                }
            }
        }
        if (player_names > best_player_names) {
            best_player_names = player_names;
            best_group = g;
        }
    }

    // If no group has non-item names, fall back to the largest group
    // that is NOT the item group (i.e., has a different vtable than group 0)
    if (best_group < 0 || best_player_names == 0) {
        printf("[!] No group with player names found.\n");
        printf("[*] Trying groups with different vtable than items...\n");

        // The largest group is likely items. Try the second-largest.
        if (groups.size() >= 2) {
            best_group = 1;
        } else {
            best_group = 0;
        }
    }

    auto& selected = groups[best_group];
    printf("[+] Selected group %d: vtable=0x%llx  SID=+0x%x  count=%d\n",
           best_group, selected.vtable, selected.sid_off, selected.count);

    // Collect players from this group
    struct PlayerObj { uint64_t base, sid; };
    std::vector<PlayerObj> players;
    std::unordered_set<uint64_t> seen;
    for (auto& [sid, addrs] : sid_locs) {
        for (auto a : addrs) {
            uint64_t base = a - selected.sid_off;
            uint64_t vt = strip_pac(r64(base));
            if (vt == selected.vtable && !seen.count(sid)) {
                seen.insert(sid);
                players.push_back({base, sid});
            }
        }
    }

    // Find name offset for this group
    int name_off = -1;
    {
        std::map<int, int> scores;
        int lim = std::min((int)players.size(), 20);
        for (int off = 0x10; off < 0xA00; off += 8) {
            for (int i = 0; i < lim; i++) {
                std::string s = read_str(players[i].base + off);
                if (s.size() >= 2 && s.size() <= 32) scores[off]++;
            }
        }
        int bs = 0;
        for (auto& [off, sc] : scores) {
            if (sc > bs) { bs = sc; name_off = off; }
        }
    }

    printf("\n=== Players in Selected Group ===\n");
    for (size_t i = 0; i < players.size() && i < 30; i++) {
        std::string nm = (name_off >= 0) ? read_str(players[i].base + name_off) : "";
        uint64_t cp = strip_pac(r64(players[i].base + 0x10));
        printf("  [%2zu] SID=...%04llu  base=0x%llx  cachedPtr=%s  %s%s\n",
               i, players[i].sid % 10000, players[i].base,
               vptr(cp) ? "VALID" : "null",
               nm.empty() ? "" : "\"",
               nm.empty() ? "(no name)" : (nm + "\"").c_str());
    }

    // =========================================================================
    // Deep walk with delta comparison
    // =========================================================================
    int obj_size = std::max(0xA00, selected.sid_off + 0x200);
    obj_size = std::min(obj_size, 0x1000);
    int n_scan = std::min((int)players.size(), 6);

    printf("\n[*] Snapshot 1 (%d players)...\n", n_scan);
    std::vector<std::map<Path, PosEntry>> snap1(n_scan);
    for (int i = 0; i < n_scan; i++) {
        auto ents = snapshot(players[i].base, obj_size);
        for (auto& e : ents) snap1[i][e.path] = e;
        printf("  Player %d: %zu candidates\n", i, ents.size());
    }

    printf("\n  ┌─────────────────────────────────────────────────┐\n");
    printf("  │  BOUGE-TOI EN JEU ! (8 secondes)                 │\n");
    printf("  └─────────────────────────────────────────────────┘\n");
    printf("  Countdown: ");
    fflush(stdout);
    for (int t = 8; t > 0; t--) { printf("%d.. ", t); fflush(stdout); sleep(1); }
    printf("GO!\n\n");

    printf("[*] Snapshot 2...\n");
    int total = 0;

    // Track per-path changes across players to find the UNIVERSAL chain
    std::map<std::tuple<int,int,int>, int> chain_hits;  // (off1_type, off2, off3) -> count

    for (int i = 0; i < n_scan; i++) {
        auto ents2 = snapshot(players[i].base, obj_size);
        int player_changes = 0;

        for (auto& e2 : ents2) {
            auto it = snap1[i].find(e2.path);
            if (it == snap1[i].end()) continue;
            auto& e1 = it->second;
            float dx = e2.x-e1.x, dy = e2.y-e1.y, dz = e2.z-e1.z;
            float d = sqrtf(dx*dx + dy*dy + dz*dz);
            if (d < 0.3f || d > 200.0f) continue;

            total++;
            player_changes++;
            auto& p = e2.path;

            // Only print first 5 changes per player
            if (player_changes <= 5) {
                printf("\n  *** Player %d (SID ...%04llu) ***\n", i, players[i].sid % 10000);
                if (p.off[1] == -1)
                    printf("      Path: base + 0x%x\n", p.off[0]);
                else if (p.off[2] == -1)
                    printf("      Path: base[+0x%x] -> +0x%x\n", p.off[0], p.off[1]);
                else if (p.off[3] == -1)
                    printf("      Path: base[+0x%x] -> [+0x%x] -> +0x%x\n", p.off[0], p.off[1], p.off[2]);
                else
                    printf("      Path: base[+0x%x] -> [+0x%x] -> [+0x%x] -> +0x%x\n",
                           p.off[0], p.off[1], p.off[2], p.off[3]);
                printf("      (%.1f, %.1f, %.1f) -> (%.1f, %.1f, %.1f)  delta=%.1fm\n",
                       e1.x, e1.y, e1.z, e2.x, e2.y, e2.z, d);

                // Print pointer chain
                printf("      [Ptrs]");
                if (p.off[1] != -1) {
                    uint64_t p1 = strip_pac(r64(players[i].base + p.off[0]));
                    printf(" -> 0x%llx", p1);
                    if (p.off[2] != -1) {
                        uint64_t p2 = strip_pac(r64(p1 + p.off[1]));
                        printf(" -> 0x%llx", p2);
                        if (p.off[3] != -1) {
                            uint64_t p3 = strip_pac(r64(p2 + p.off[2]));
                            printf(" -> 0x%llx", p3);
                        }
                    }
                }
                printf("\n");
            }

            // Track chain pattern (ignoring base offset which varies)
            if (p.off[1] != -1) {
                chain_hits[{p.off[1], p.off[2], p.off[3]}]++;
            }
        }
        if (player_changes > 5) {
            printf("  ... and %d more changes for player %d\n", player_changes - 5, i);
        }
    }

    printf("\n  ══════════════════════════════════════════════════\n");
    printf("  Total changes: %d\n", total);
    printf("  ══════════════════════════════════════════════════\n");

    if (total > 0 && !chain_hits.empty()) {
        printf("\n=== Most Common Chains (across all players) ===\n");
        std::vector<std::pair<std::tuple<int,int,int>, int>> sorted_chains(chain_hits.begin(), chain_hits.end());
        std::sort(sorted_chains.begin(), sorted_chains.end(),
                  [](auto& a, auto& b) { return a.second > b.second; });
        for (size_t i = 0; i < sorted_chains.size() && i < 10; i++) {
            auto& [chain, cnt] = sorted_chains[i];
            auto [a, b, c] = chain;
            printf("  %3d hits: ", cnt);
            if (b == -1) printf("-> +0x%x\n", a);
            else if (c == -1) printf("-> [+0x%x] -> +0x%x\n", a, b);
            else printf("-> [+0x%x] -> [+0x%x] -> +0x%x\n", a, b, c);
        }
    }

    if (total == 0) {
        printf("\n[!] No changes. BOUGE en jeu pendant le countdown !\n");
    }

    return 0;
}
