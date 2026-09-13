// =============================================================================
// live_pos.cpp — Autonomous live-position discovery for Rust (macOS ARM64)
//
// Strategy (fully autonomous, no user input needed):
//  1. Find BasePlayer objects: scan RW regions for SteamIDs in range, verify
//     each candidate has a valid m_CachedPtr at +0x10 (real managed object).
//  2. Identify the LOCAL player by known SID (76561198984296471).
//  3. Delta-scan in a LOOP: for each player object, snapshot managed object
//     (0x1000) + native object (0x800), sleep, re-snapshot, find Vector3s that
//     moved. Repeat R rounds — someone on the server always moves.
//  4. A path that moves consistently across rounds = LIVE POSITION for that
//     player. Output table + JSON radar_data.json.
//
// Compile: c++ -O2 -std=c++17 -o live_pos live_pos.cpp
// Run:     sudo ./live_pos [rounds=12] [sleep=3]
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
static uint64_t r64(uint64_t a) { uint64_t v = 0; rmem(a, &v, 8); return v; }
static uint64_t spac(uint64_t p) { return p & 0x0000FFFFFFFFFFFFULL; }
static bool vp(uint64_t p) { uint64_t s = spac(p); return s > 0x10000ULL && s < 0x7FFFFFFFFFFFULL; }

static pid_t find_rust() {
    pid_t pids[8192]; int n = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    for (int i = 0; i < n / (int)sizeof(pid_t); i++) {
        if (!pids[i]) continue; char path[PROC_PIDPATHINFO_MAXSIZE] = {};
        if (proc_pidpath(pids[i], path, sizeof(path)) > 0 && strstr(path, "Rust")) return pids[i];
    }
    return -1;
}

struct Rg { uint64_t s, e; };
static std::vector<Rg> g_rw;
static void enum_rg() {
    mach_vm_address_t a = 0; mach_vm_size_t sz; vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt; mach_port_t obj;
    while (true) {
        cnt = VM_REGION_BASIC_INFO_COUNT_64;
        if (mach_vm_region(g_task, &a, &sz, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &cnt, &obj) != KERN_SUCCESS) break;
        if ((info.protection & VM_PROT_READ) && (info.protection & VM_PROT_WRITE)) g_rw.push_back({a, a + sz});
        a += sz;
    }
}

static const uint64_t SMIN = 76561198000000000ULL, SMAX = 76561200000000000ULL;
static const uint64_t MY_SID = 76561198984296471ULL;

struct Player {
    uint64_t addr;   // managed object address
    uint64_t native; // m_CachedPtr at +0x10
    uint64_t sid;
    int sid_off;
    bool is_me;
};

// ---- Step 1: find players by SID scan + m_CachedPtr validation ----
static std::vector<Player> find_players() {
    std::vector<Player> out;
    std::unordered_map<uint64_t, std::vector<std::pair<uint64_t,int>>> cand; // obj_addr -> (sid, off)
    const size_t C = 4 * 1024 * 1024;
    std::vector<uint8_t> buf(C);
    for (auto& r : g_rw) {
        uint64_t rs = r.e - r.s;
        if (rs > 512ULL * 1024 * 1024) continue;
        for (uint64_t o = 0; o < rs; o += C) {
            uint64_t tr = std::min((uint64_t)C, rs - o);
            mach_vm_size_t got = 0;
            if (mach_vm_read_overwrite(g_task, r.s + o, tr, (vm_address_t)buf.data(), &got) != KERN_SUCCESS) break;
            for (size_t i = 0; i + 8 <= (size_t)got; i += 8) {
                uint64_t v; memcpy(&v, buf.data() + i, 8);
                if (v >= SMIN && v < SMAX) {
                    uint64_t obj = r.s + o + i - 0x130; // SID typically at +0x130
                    cand[obj].push_back({v, (int)(i - 0x130)});
                }
            }
        }
    }
    printf("[+] %zu SID candidate objects\n", cand.size());
    // Validate: object +0x00 points to a known-class-looking vtable (readable),
    // +0x10 is a valid m_CachedPtr (native pointer), and SID re-read matches.
    for (auto& [obj, sids] : cand) {
        if (!vp(obj) || !vp(obj + 0x10)) continue;
        uint64_t native = spac(r64(obj + 0x10));
        if (!vp(native)) continue;
        // Re-read SID at the claimed offset to confirm stability
        uint64_t sid = r64(obj + 0x130);
        bool ok = false;
        for (auto& [s, off] : sids) if (s == sid) { ok = true; break; }
        if (!ok) continue;
        // Native object must be readable and contain plausible data
        uint8_t probe[64];
        if (!rmem(native, probe, 64)) continue;
        Player p{obj, native, sid, 0x130, sid == MY_SID};
        out.push_back(p);
    }
    // dedup by addr
    std::sort(out.begin(), out.end(), [](auto& a, auto& b) { return a.addr < b.addr; });
    out.erase(std::unique(out.begin(), out.end(), [](auto& a, auto& b) { return a.addr == b.addr; }), out.end());
    return out;
}

// ---- Step 3: DIRECT float delta (no pointer walk — low noise) ----
static bool is_wp(float x, float y, float z) {
    if (!std::isfinite(x) || !std::isfinite(y) || !std::isfinite(z)) return false;
    if (x < -5000 || x > 5000 || z < -5000 || z > 5000) return false;
    if (y < -500 || y > 3000) return false;
    return sqrtf(x * x + z * z) > 1.0f;
}

struct Path { int off[2]; // [base_tag, offset]
    bool operator<(const Path& o) const {
        if (off[0] != o.off[0]) return off[0] < o.off[0];
        return off[1] < o.off[1];
    }
};
struct PE { Path path; float x, y, z; };

// Direct scan of a contiguous buffer for valid world-position floats
static void sf_direct(const uint8_t* b, int len, int base_tag, std::vector<PE>& out) {
    for (int f = 0; f + 12 <= len; f += 4) {
        float x, y, z;
        memcpy(&x, b + f, 4); memcpy(&y, b + f + 4, 4); memcpy(&z, b + f + 8, 4);
        if (!is_wp(x, y, z)) continue;
        out.push_back({{base_tag, f}, x, y, z});
    }
}

// Snapshot: managed object (0x1000, tag 0) + native object (0x800, tag 1)
static std::vector<PE> snap(uint64_t obj_addr, uint64_t native_addr) {
    std::vector<PE> res;
    uint8_t b0[0x1000]; if (rmem(obj_addr, b0, 0x1000)) sf_direct(b0, 0x1000, 0, res);
    uint8_t b1[0x800];  if (rmem(native_addr, b1, 0x800)) sf_direct(b1, 0x800, 1, res);
    return res;
}

// ---- main ----
int main(int argc, char** argv) {
    int ROUNDS = argc > 1 ? atoi(argv[1]) : 12;
    int SLEEP_S = argc > 2 ? atoi(argv[2]) : 3;

    printf("\n  ╔══════════════════════════════════════╗\n");
    printf("  ║  live_pos — autonomous position finder ║\n");
    printf("  ╚══════════════════════════════════════╝\n\n");

    pid_t pid = find_rust();
    if (pid < 0) { printf("[!] Rust not found\n"); return 1; }
    printf("[+] Rust PID=%d\n", pid);
    if (task_for_pid(mach_task_self(), pid, &g_task) != KERN_SUCCESS) {
        printf("[!] task_for_pid failed\n"); return 1;
    }
    enum_rg();
    printf("[+] %zu RW regions\n", g_rw.size());

    auto players = find_players();
    printf("[+] %zu validated BasePlayer objects\n", players.size());
    int me_idx = -1;
    for (size_t i = 0; i < players.size(); i++) {
        if (players[i].is_me) { me_idx = (int)i; printf("    [%zu] ★ LOCAL (SID=%llu) addr=0x%llx native=0x%llx\n", i, players[i].sid, players[i].addr, players[i].native); }
        else if (i < 12) printf("    [%zu] SID=%llu addr=0x%llx native=0x%llx\n", i, players[i].sid, players[i].addr, players[i].native);
    }
    if (players.size() > 12) printf("    ... %zu more\n", players.size() - 12);
    if (players.empty()) return 1;

    // ---- multi-round delta scan ----
    int N = (int)players.size();
    // hit[player][pathkey] = number of rounds this path moved
    std::map<std::pair<int, std::string>, int> hits;
    std::map<std::pair<int, std::string>, PE> last_pos;

    printf("\n[*] Delta-scan: %d rounds x %ds — positions live automatiquement\n", ROUNDS, SLEEP_S);
    for (int round = 0; round < ROUNDS; round++) {
        // Snapshot 1
        std::vector<std::map<Path, PE>> s1(N);
        for (int i = 0; i < N; i++) {
            auto es = snap(players[i].addr, players[i].native);
            for (auto& e : es) s1[i][e.path] = e;
        }
        sleep(SLEEP_S);
        int round_hits = 0;
        for (int i = 0; i < N; i++) {
            auto es2 = snap(players[i].addr, players[i].native);
            for (auto& e2 : es2) {
                auto it = s1[i].find(e2.path);
                if (it == s1[i].end()) continue;
                auto& e1 = it->second;
                float dx = e2.x - e1.x, dy = e2.y - e1.y, dz = e2.z - e1.z;
                float d = sqrtf(dx * dx + dy * dy + dz * dz);
                if (d < 0.3f || d > 300.0f) continue;
                char key[64];
                snprintf(key, 64, "%s+0x%x", e2.path.off[0] ? "native" : "base", e2.path.off[1]);
                hits[{i, key}]++;
                last_pos[{i, key}] = e2;
                round_hits++;
            }
        }
        printf("  round %2d: %d movements\n", round, round_hits);
        fflush(stdout);
    }

    // ---- report: paths that moved in >= 2 rounds are live positions ----
    printf("\n  ═══════════════════════════════════════════\n");
    printf("  STABLE LIVE POSITIONS (>=2 rounds)\n");
    printf("  ═══════════════════════════════════════════\n");
    int stable = 0;
    for (auto& [pk, cnt] : hits) {
        if (cnt < 2) continue;
        int i = pk.first; auto& key = pk.second;
        auto& e = last_pos[{i, key}];
        printf("  [%d] %s SID=%llu %s  -> (%.1f, %.1f, %.1f)  (%d rounds)\n",
               i, players[i].is_me ? "★ME" : "   ", players[i].sid, key.c_str(), e.x, e.y, e.z, cnt);
        stable++;
    }
    if (stable == 0) printf("  (aucun chemin stable — augmente ROUNDS)\n");

    // ---- JSON output ----
    FILE* f = fopen("/Users/mac/Desktop/RR02/radar_data.json", "w");
    if (f) {
        fprintf(f, "{\n  \"local\": {\"x\": 0.00, \"y\": 0.00, \"z\": 0.00, \"name\": \"local\"},\n  \"players\": [\n");
        bool first = true;
        for (auto& [pk, cnt] : hits) {
            if (cnt < 2) continue;
            int i = pk.first; auto& key = pk.second;
            auto& e = last_pos[{i, key}];
            if (!first) fprintf(f, ",\n");
            first = false;
            fprintf(f, "    {\"name\":\"p%d\",\"x\":%.2f,\"y\":%.2f,\"z\":%.2f,\"sid\":%llu,\"path\":\"%s\",\"rounds\":%d,\"me\":%d}",
                    i, e.x, e.y, e.z, players[i].sid, key.c_str(), cnt, players[i].is_me ? 1 : 0);
        }
        fprintf(f, "\n  ]\n}\n");
        fclose(f);
        printf("\n[+] JSON -> /Users/mac/Desktop/RR02/radar_data.json\n");
    }
    return 0;
}
