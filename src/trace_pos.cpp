// =============================================================================
// trace_pos.cpp — Deep pointer walk to find live player positions
//
// This tool solves the position problem by brute-forcing ALL pointer chains
// from BasePlayer objects (found via SteamID scan) up to 4 levels deep,
// taking two snapshots 6 seconds apart, and reporting which chains have
// float triplets that changed (= live position data).
//
// Compile: c++ -O2 -std=c++17 -o trace_pos trace_pos.cpp
// Run:     sudo ./trace_pos
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

// =============================================================================
// Memory
// =============================================================================
static task_t g_task;

static bool rmem(uint64_t addr, void* buf, size_t size) {
    vm_size_t got = 0;
    kern_return_t kr = vm_read_overwrite(g_task, (vm_address_t)addr, size,
                                         (vm_address_t)buf, &got);
    return kr == KERN_SUCCESS && (size_t)got == size;
}

static uint64_t r64(uint64_t a) { uint64_t v = 0; rmem(a, &v, 8); return v; }
static float    rf(uint64_t a)  { float v = 0;    rmem(a, &v, 4); return v; }

// ARM64 PAC: strip pointer authentication bits
static uint64_t strip_pac(uint64_t p) {
    return p & 0x0000FFFFFFFFFFFFULL;
}

static bool vptr(uint64_t p) {
    uint64_t s = strip_pac(p);
    return s > 0x10000ULL && s < 0x7FFFFFFFFFFFULL;
}

// =============================================================================
// Process
// =============================================================================
static pid_t find_rust() {
    pid_t pids[8192];
    int n = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    for (int i = 0; i < n / (int)sizeof(pid_t); i++) {
        if (pids[i] == 0) continue;
        char path[PROC_PIDPATHINFO_MAXSIZE] = {};
        if (proc_pidpath(pids[i], path, sizeof(path)) > 0) {
            if (strstr(path, "Rust")) return pids[i];
        }
    }
    return -1;
}

// =============================================================================
// Regions
// =============================================================================
struct Region { uint64_t start, end; uint32_t prot; };
static std::vector<Region> g_rw_regions;  // For SteamID scan (heap)

static void enum_regions() {
    mach_vm_address_t addr = 0;
    mach_vm_size_t sz;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt;
    mach_port_t obj;
    while (true) {
        cnt = VM_REGION_BASIC_INFO_COUNT_64;
        if (mach_vm_region(g_task, &addr, &sz, VM_REGION_BASIC_INFO_64,
                           (vm_region_info_t)&info, &cnt, &obj) != KERN_SUCCESS)
            break;
        if ((info.protection & VM_PROT_READ) && (info.protection & VM_PROT_WRITE))
            g_rw_regions.push_back({addr, addr + sz, (uint32_t)info.protection});
        addr += sz;
    }
}

// =============================================================================
// SteamID scanning
// =============================================================================
static const uint64_t SID_MIN = 76561198000000000ULL;
static const uint64_t SID_MAX = 76561200000000000ULL;

struct SidHit { uint64_t addr, sid; };

static std::vector<SidHit> scan_sids() {
    std::vector<SidHit> hits;
    const size_t CHUNK = 4 * 1024 * 1024;
    std::vector<uint8_t> buf(CHUNK);

    for (auto& rg : g_rw_regions) {
        uint64_t rsz = rg.end - rg.start;
        if (rsz > 512ULL * 1024 * 1024) continue;
        for (uint64_t off = 0; off < rsz; off += CHUNK) {
            uint64_t toread = std::min((uint64_t)CHUNK, rsz - off);
            mach_vm_size_t got = 0;
            if (mach_vm_read_overwrite(g_task, rg.start + off, toread,
                                        (vm_address_t)buf.data(), &got) != KERN_SUCCESS)
                break;
            for (size_t i = 0; i + 8 <= (size_t)got; i += 8) {
                uint64_t v;
                memcpy(&v, buf.data() + i, 8);
                if (v >= SID_MIN && v < SID_MAX)
                    hits.push_back({rg.start + off + i, v});
            }
        }
    }
    return hits;
}

// =============================================================================
// Vtable grouping — find BasePlayer objects
// =============================================================================
struct PlayerInfo {
    uint64_t base, sid;
    int sid_off;
};

static std::vector<PlayerInfo> find_players(const std::vector<SidHit>& hits) {
    // Group hits by unique SID
    std::unordered_map<uint64_t, std::vector<uint64_t>> sid_locs;
    for (auto& h : hits) sid_locs[h.sid].push_back(h.addr);
    printf("[*] %zu unique SteamIDs\n", sid_locs.size());
    if (sid_locs.empty()) return {};

    // Try all possible SID offsets within an object, group by first qword (vtable)
    int best_soff = 0;
    uint64_t best_vt = 0;
    int best_cnt = 0;

    for (int soff = 0x10; soff <= 0xA00; soff += 0x08) {
        std::unordered_map<uint64_t, int> vt_cnt;
        for (auto& [sid, addrs] : sid_locs) {
            uint64_t base = addrs[0] - soff;
            uint64_t vt = strip_pac(r64(base));
            if (vptr(vt)) vt_cnt[vt]++;
        }
        for (auto& [vt, c] : vt_cnt) {
            if (c > best_cnt) { best_cnt = c; best_vt = vt; best_soff = soff; }
        }
    }

    printf("[+] vtable = 0x%llx\n", best_vt);
    printf("[+] SID offset = +0x%x\n", best_soff);
    printf("[+] %d players match\n", best_cnt);

    if (best_cnt < 2) {
        printf("[!] Too few matching players — results may be unreliable\n");
    }

    // Collect unique players
    std::vector<PlayerInfo> out;
    std::unordered_set<uint64_t> seen;
    for (auto& [sid, addrs] : sid_locs) {
        for (auto a : addrs) {
            uint64_t base = a - best_soff;
            uint64_t vt = strip_pac(r64(base));
            if (vt == best_vt && !seen.count(sid)) {
                seen.insert(sid);
                out.push_back({base, sid, best_soff});
            }
        }
    }
    return out;
}

// =============================================================================
// IL2CPP string reading
// =============================================================================
static std::string read_il2str(uint64_t ptr_addr) {
    uint64_t str = strip_pac(r64(ptr_addr));
    if (!vptr(str)) return "";
    uint32_t len = 0;
    rmem(str + 0x10, &len, 4);
    if (len == 0 || len > 64) return "";
    std::string out;
    for (uint32_t i = 0; i < len && i < 63; i++) {
        uint16_t c = 0;
        rmem(str + 0x14 + i * 2, &c, 2);
        if (c == 0) break;
        if (c >= 32 && c < 127) out += (char)c;
    }
    return out.size() >= 2 ? out : "";
}

// Auto-detect name offset by scanning for IL2CPP strings across players
static int find_name_offset(const std::vector<PlayerInfo>& players) {
    std::map<int, int> scores;
    int limit = std::min((int)players.size(), 20);
    for (int off = 0x10; off < 0xA00; off += 8) {
        for (int i = 0; i < limit; i++) {
            std::string s = read_il2str(players[i].base + off);
            if (s.size() >= 2 && s.size() <= 32) scores[off]++;
        }
    }
    int best_off = -1, best_sc = 0;
    for (auto& [off, sc] : scores) {
        if (sc > best_sc) { best_sc = sc; best_off = off; }
    }
    return best_sc >= 2 ? best_off : -1;
}

// =============================================================================
// Position scanning — deep pointer walk
// =============================================================================

static bool is_world_pos(float x, float y, float z) {
    if (!std::isfinite(x) || !std::isfinite(y) || !std::isfinite(z)) return false;
    if (x < -5000 || x > 5000 || z < -5000 || z > 5000) return false;
    if (y < -500 || y > 3000) return false;
    float mag = sqrtf(x * x + z * z);
    return mag > 15.0f;  // Skip positions too close to origin
}

// A path through the pointer chain: up to 4 offsets
// off[0] = offset in BasePlayer to follow
// off[1] = offset in level-1 object (-1 = float read here)
// off[2] = offset in level-2 object (-1 = float read here)
// off[3] = float offset in level-3 object (-1 = not used)
struct Path {
    int off[4];
    bool operator<(const Path& o) const {
        for (int i = 0; i < 4; i++) {
            if (off[i] != o.off[i]) return off[i] < o.off[i];
        }
        return false;
    }
    bool operator==(const Path& o) const {
        return off[0] == o.off[0] && off[1] == o.off[1] &&
               off[2] == o.off[2] && off[3] == o.off[3];
    }
};

struct PosEntry { Path path; float x, y, z; };

// Scan a buffer for world-coordinate float triplets
static void scan_floats_in_buf(const uint8_t* buf, int bufsize,
                                int o1, int o2, int o3,
                                std::vector<PosEntry>& out) {
    for (int fo = 0; fo + 12 <= bufsize; fo += 4) {
        float x, y, z;
        memcpy(&x, buf + fo, 4);
        memcpy(&y, buf + fo + 4, 4);
        memcpy(&z, buf + fo + 8, 4);
        if (is_world_pos(x, y, z)) {
            Path p;
            if (o2 == -99) {
                // Level 0: direct float in base object
                p = {fo, -1, -1, -1};
            } else if (o3 == -99) {
                // Level 1: base[o1] -> float at fo
                p = {o1, fo, -1, -1};
            } else if (o3 == -98) {
                // Level 2: base[o1] -> [o2] -> float at fo
                p = {o1, o2, fo, -1};
            } else {
                // Level 3: base[o1] -> [o2] -> [o3] -> float at fo
                p = {o1, o2, o3, fo};
            }
            out.push_back({p, x, y, z});
        }
    }
}

static const int BASE_READ  = 0xA00;  // Bytes to read from BasePlayer
static const int L1_READ    = 0x500;  // Bytes to read from level-1 objects
static const int L2_READ    = 0x400;  // Bytes to read from level-2 objects
static const int L3_READ    = 0x400;  // Bytes to read from level-3 objects
static const int PTR_RANGE2 = 0x200;  // Range to follow pointers in sub-objects
static const int PTR_RANGE3 = 0x100;  // Range to follow pointers at level 3

static std::vector<PosEntry> snapshot_player(uint64_t base, int obj_size) {
    std::vector<PosEntry> results;

    // Read the BasePlayer managed object
    std::vector<uint8_t> buf0(obj_size);
    if (!rmem(base, buf0.data(), obj_size)) return results;

    // === Level 0: Direct floats in BasePlayer ===
    scan_floats_in_buf(buf0.data(), obj_size, 0, -99, -99, results);

    // === Level 1+: Follow pointers from BasePlayer ===
    std::unordered_set<uint64_t> vis1;
    for (int o1 = 0; o1 + 8 <= obj_size; o1 += 8) {
        uint64_t p1;
        memcpy(&p1, buf0.data() + o1, 8);
        p1 = strip_pac(p1);
        if (!vptr(p1) || p1 == strip_pac(r64(base))) continue;  // skip vtable self-ref
        if (vis1.count(p1)) continue;
        vis1.insert(p1);

        uint8_t buf1[L1_READ];
        if (!rmem(p1, buf1, L1_READ)) continue;

        // Level 1 floats
        scan_floats_in_buf(buf1, L1_READ, o1, -99, -99, results);

        // === Level 2: Follow sub-pointers ===
        std::unordered_set<uint64_t> vis2;
        for (int o2 = 0; o2 + 8 <= PTR_RANGE2; o2 += 8) {
            uint64_t p2;
            memcpy(&p2, buf1 + o2, 8);
            p2 = strip_pac(p2);
            if (!vptr(p2) || vis2.count(p2)) continue;
            vis2.insert(p2);

            uint8_t buf2[L2_READ];
            if (!rmem(p2, buf2, L2_READ)) continue;

            // Level 2 floats
            scan_floats_in_buf(buf2, L2_READ, o1, o2, -98, results);

            // === Level 3: One more dereference ===
            for (int o3 = 0; o3 + 8 <= PTR_RANGE3; o3 += 8) {
                uint64_t p3;
                memcpy(&p3, buf2 + o3, 8);
                p3 = strip_pac(p3);
                if (!vptr(p3)) continue;

                uint8_t buf3[L3_READ];
                if (!rmem(p3, buf3, L3_READ)) continue;

                // Level 3 floats
                scan_floats_in_buf(buf3, L3_READ, o1, o2, o3, results);
            }
        }
    }

    return results;
}

// =============================================================================
// Print the path in human-readable form
// =============================================================================
static void print_path(const Path& p) {
    if (p.off[1] == -1) {
        printf("      Path: base + 0x%x  (direct float)\n", p.off[0]);
    } else if (p.off[2] == -1) {
        printf("      Path: base[+0x%x] -> +0x%x\n", p.off[0], p.off[1]);
    } else if (p.off[3] == -1) {
        printf("      Path: base[+0x%x] -> [+0x%x] -> +0x%x\n",
               p.off[0], p.off[1], p.off[2]);
    } else {
        printf("      Path: base[+0x%x] -> [+0x%x] -> [+0x%x] -> +0x%x\n",
               p.off[0], p.off[1], p.off[2], p.off[3]);
    }
}

// =============================================================================
// Main
// =============================================================================
int main() {
    printf("\n");
    printf("  ╔═══════════════════════════════════════════════╗\n");
    printf("  ║  TRACE_POS v2 — Deep Position Finder          ║\n");
    printf("  ║  Follows ALL pointer chains from BasePlayer    ║\n");
    printf("  ║  4 levels deep, with delta comparison          ║\n");
    printf("  ╚═══════════════════════════════════════════════╝\n\n");

    // --- Phase 1: Find Rust ---
    pid_t pid = find_rust();
    if (pid < 0) {
        printf("[!] Rust process not found. Launch the game first.\n");
        return 1;
    }
    printf("[+] Rust PID = %d\n", pid);

    if (task_for_pid(mach_task_self(), pid, &g_task) != KERN_SUCCESS) {
        printf("[!] task_for_pid failed — run with sudo\n");
        return 1;
    }

    // --- Phase 2: Enumerate regions ---
    enum_regions();
    printf("[+] %zu read-write regions\n", g_rw_regions.size());

    // --- Phase 3: Scan for SteamIDs ---
    printf("[*] Scanning heap for SteamIDs...\n");
    auto hits = scan_sids();
    printf("[+] %zu SteamID hits in memory\n", hits.size());
    if (hits.empty()) {
        printf("[!] No SteamIDs found. Are you connected to a server?\n");
        return 1;
    }

    // --- Phase 4: Find BasePlayer objects ---
    auto players = find_players(hits);
    printf("[+] %zu unique players\n\n", players.size());
    if (players.empty()) {
        printf("[!] No players identified\n");
        return 1;
    }

    // --- Phase 5: Find names ---
    int name_off = find_name_offset(players);
    if (name_off >= 0) printf("[+] Name offset = +0x%x\n", name_off);

    // m_CachedPtr diagnostic
    printf("\n=== Player List ===\n");
    for (size_t i = 0; i < players.size() && i < 30; i++) {
        std::string name = (name_off >= 0) ? read_il2str(players[i].base + name_off) : "";
        uint64_t cached_ptr = strip_pac(r64(players[i].base + 0x10));
        uint64_t cached_ptr2 = strip_pac(r64(players[i].base + 0x18));
        printf("  [%2zu] SID=...%04llu  base=0x%llx  m_CachedPtr=0x%llx",
               i, players[i].sid % 10000, players[i].base,
               vptr(cached_ptr) ? cached_ptr : 0);
        if (!name.empty()) printf("  \"%s\"", name.c_str());
        printf("\n");
    }

    // --- Phase 6: Object size ---
    int obj_size = std::max(BASE_READ, players[0].sid_off + 0x200);
    obj_size = std::min(obj_size, 0x1000);

    // --- Phase 7: Snapshot 1 ---
    int n_scan = std::min((int)players.size(), 6);  // Scan up to 6 players
    printf("\n[*] Taking snapshot 1 (%d players, read 0x%x bytes each)...\n",
           n_scan, obj_size);

    std::vector<std::map<Path, PosEntry>> snap1(n_scan);
    for (int i = 0; i < n_scan; i++) {
        auto entries = snapshot_player(players[i].base, obj_size);
        for (auto& e : entries) snap1[i][e.path] = e;
        printf("  Player %d (SID ...%04llu): %zu position candidates\n",
               i, players[i].sid % 10000, entries.size());
    }

    // --- Phase 8: Wait for movement ---
    printf("\n");
    printf("  ┌─────────────────────────────────────────────────┐\n");
    printf("  │  BOUGE-TOI EN JEU MAINTENANT !                   │\n");
    printf("  │                                                   │\n");
    printf("  │  Marche en ligne droite pendant 6 secondes.       │\n");
    printf("  │  Ne t'arrête PAS avant que le scan reprenne.      │\n");
    printf("  └─────────────────────────────────────────────────┘\n");
    printf("\n  Countdown: ");
    fflush(stdout);
    for (int t = 6; t > 0; t--) {
        printf("%d... ", t);
        fflush(stdout);
        sleep(1);
    }
    printf("GO!\n\n");

    // --- Phase 9: Snapshot 2 ---
    printf("[*] Taking snapshot 2...\n");

    int total_changes = 0;

    // Track which chains show changes across multiple players
    std::map<std::tuple<int,int,int,int>, int> chain_frequency;

    for (int i = 0; i < n_scan; i++) {
        auto entries2 = snapshot_player(players[i].base, obj_size);

        for (auto& e2 : entries2) {
            auto it = snap1[i].find(e2.path);
            if (it == snap1[i].end()) continue;

            auto& e1 = it->second;
            float dx = e2.x - e1.x;
            float dy = e2.y - e1.y;
            float dz = e2.z - e1.z;
            float dmag = sqrtf(dx*dx + dy*dy + dz*dz);

            // Realistic movement: 0.3m to 200m in 6 seconds
            if (dmag > 0.3f && dmag < 200.0f) {
                total_changes++;
                auto& p = e2.path;
                auto chain_key = std::make_tuple(
                    p.off[1] == -1 ? -2 : 0, // level indicator
                    p.off[2] == -1 ? p.off[1] : p.off[1],
                    p.off[3] == -1 ? p.off[2] : p.off[2],
                    p.off[3]
                );
                // Simplified chain key: just the offsets without the base offset
                // (base offset varies per player for shared sub-objects)

                printf("\n  *** CHANGE — Player %d (SID ...%04llu) ***\n",
                       i, players[i].sid % 10000);
                print_path(p);
                printf("      Before: (%.2f, %.2f, %.2f)\n", e1.x, e1.y, e1.z);
                printf("      After:  (%.2f, %.2f, %.2f)\n", e2.x, e2.y, e2.z);
                printf("      Delta:  %.1fm\n", dmag);

                // Debug: print pointer values along the chain
                printf("      [Ptrs]");
                uint64_t cur = players[i].base;
                if (p.off[1] != -1) {
                    uint64_t p1 = strip_pac(r64(cur + p.off[0]));
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
        }
    }

    // --- Phase 10: Summary ---
    printf("\n");
    printf("  ══════════════════════════════════════════════════\n");
    printf("  Total position changes detected: %d\n", total_changes);
    printf("  ══════════════════════════════════════════════════\n");

    if (total_changes > 0) {
        printf("\n  ╔═══════════════════════════════════════════════╗\n");
        printf("  ║  SUCCESS! Position chain(s) found above.       ║\n");
        printf("  ║                                                 ║\n");
        printf("  ║  Use the Path info to update radar.cpp:         ║\n");
        printf("  ║                                                 ║\n");
        printf("  ║  For 'base[+A] -> +B':                         ║\n");
        printf("  ║    uint64_t obj = r64(base + A);               ║\n");
        printf("  ║    float x = rf(obj + B);                      ║\n");
        printf("  ║    float y = rf(obj + B + 4);                  ║\n");
        printf("  ║    float z = rf(obj + B + 8);                  ║\n");
        printf("  ║                                                 ║\n");
        printf("  ║  For 'base[+A] -> [+B] -> +C':                 ║\n");
        printf("  ║    uint64_t o1 = r64(base + A);                ║\n");
        printf("  ║    uint64_t o2 = r64(o1 + B);                  ║\n");
        printf("  ║    float x = rf(o2 + C);                      ║\n");
        printf("  ║    float y = rf(o2 + C + 4);                  ║\n");
        printf("  ║    float z = rf(o2 + C + 8);                  ║\n");
        printf("  ╚═══════════════════════════════════════════════╝\n");
    } else {
        printf("\n[!] Aucun changement detecte.\n");
        printf("    Causes possibles:\n");
        printf("    1. Tu n'as PAS bouge pendant les 6 secondes\n");
        printf("    2. La position est a plus de 4 niveaux de profondeur\n");
        printf("    3. Les pointers utilisent un encoding special (PAC)\n");
        printf("    4. La position utilise un format non-standard\n");
        printf("\n    -> Relance le programme et BOUGE des le countdown!\n");
    }

    return 0;
}
