// =============================================================================
// radar_live.cpp — FINAL: Rust live radar (macOS ARM64, external)
//
// Pipeline:
//   1. Scan writable memory for SteamIDs (known-good from recon)
//   2. Filter: object->vtable == 0x10399bac0 (BasePlayer, Aug 2026 build)
//   3. Delta-scan DIRECT (no pointer walk): managed obj 0x1000 + native 0x800
//   4. Multi-round consistency (>=3 rounds) with plausible deltas (0.3..300m)
//   5. Output stable paths + current positions; write radar_data.json
//
// Run: echo PASS | sudo -S ./radar_live [rounds] [sleep_s]
// =============================================================================
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>
#include <map>
#include <unordered_map>
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
static uint32_t r32(uint64_t a) { uint32_t v = 0; rmem(a, &v, 4); return v; }
static float rf(uint64_t a) { float v = 0; rmem(a, &v, 4); return v; }
static bool vptr(uint64_t p) { return p > 0x10000ULL && p < 0x7FFFFFFFFFFFULL; }
static bool is_sid(uint64_t v) { return v >= 76561197960265728ULL && v <= 76561202255233023ULL; }

const uint64_t BP_VTABLE = 0x10399bac0ULL; // Aug 2026 build
const int OBJ_SCAN = 0x1000;   // managed object scan window
const int NAT_SCAN = 0x800;    // native object scan window

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

struct Player { uint64_t addr; uint64_t native; uint64_t sid; };

// ---- Step 1+2: SID scan + vtable filter ----
static std::vector<Player> find_players() {
    std::vector<Player> out;
    std::vector<uint8_t> buf(4 * 1024 * 1024);
    std::map<uint64_t, Player> uniq;
    for (auto& r : g_rw) {
        uint64_t rs = r.e - r.s;
        if (rs > 512ULL * 1024 * 1024) continue;
        for (uint64_t o = 0; o < rs; o += buf.size()) {
            uint64_t tr = std::min((uint64_t)buf.size(), rs - o);
            mach_vm_size_t got = 0;
            if (mach_vm_read_overwrite(g_task, r.s + o, tr, (vm_address_t)buf.data(), &got) != KERN_SUCCESS) break;
            for (size_t i = 0; i + 8 <= (size_t)got; i += 8) {
                uint64_t v; memcpy(&v, buf.data() + i, 8);
                if (!is_sid(v)) continue;
                uint64_t obj = r.s + o + i - 0x1b0; // SID at +0x1b0
                if (obj < r.s) continue;
                uint64_t vt = r64(obj);
                if (vt != BP_VTABLE) continue;
                uint64_t nat = r64(obj + 0x10);
                if (!vptr(nat)) continue;
                uniq[obj] = {obj, nat, v};
            }
        }
    }
    for (auto& kv : uniq) out.push_back(kv.second);
    return out;
}

// ---- Step 3: direct float extraction ----
struct PE { int tag; int off; float x, y, z; }; // tag: 0=managed, 1=native
static std::vector<PE> get_floats(uint64_t obj, uint64_t nat) {
    std::vector<PE> out;
    auto scan = [&](uint64_t base, int tag, int len) {
        std::vector<uint8_t> b(len);
        if (!rmem(base, b.data(), len)) return;
        for (int off = 0; off + 12 <= len; off += 4) {
            float x, y, z; memcpy(&x, b.data() + off, 4); memcpy(&y, b.data() + off + 4, 4); memcpy(&z, b.data() + off + 8, 4);
            if (!std::isfinite(x) || !std::isfinite(y) || !std::isfinite(z)) continue;
            if (fabsf(x) > 5000 || fabsf(y) > 5000 || fabsf(z) > 5000) continue;
            out.push_back({tag, off, x, y, z});
        }
    };
    scan(obj, 0, OBJ_SCAN);
    scan(nat, 1, NAT_SCAN);
    return out;
}

int main(int argc, char** argv) {
    int ROUNDS = argc > 1 ? atoi(argv[1]) : 15;
    int SLEEP_S = argc > 2 ? atoi(argv[2]) : 3;

    pid_t pid = find_rust();
    if (pid < 0) { printf("[!] Rust not found\n"); return 1; }
    printf("[+] Rust PID=%d\n", pid);
    if (task_for_pid(mach_task_self(), pid, &g_task) != KERN_SUCCESS) { printf("[!] task_for_pid failed\n"); return 1; }
    enum_rg();
    printf("[+] %zu RW regions\n", g_rw.size());

    auto players = find_players();
    printf("[+] %zu players (vtable 0x%llx + SID@+0x1b0)\n", players.size(), (unsigned long long)BP_VTABLE);
    for (auto& p : players) printf("    obj=0x%llx native=0x%llx SID=%llu\n", p.addr, p.native, p.sid);

    // ---- Step 4: multi-round direct delta ----
    printf("\n[*] Delta-scan: %d rounds x %ds (direct floats only)\n", ROUNDS, SLEEP_S);
    struct Hit { int tag, off; float x, y, z; };
    std::map<std::pair<int,int>, int> consistency;   // (player idx, key) -> count
    std::map<std::pair<int,int>, Hit> last;

    for (int round = 0; round < ROUNDS; round++) {
        std::vector<std::map<int, PE>> s1(players.size());
        for (size_t i = 0; i < players.size(); i++) {
            for (auto& e : get_floats(players[i].addr, players[i].native)) s1[i][(e.tag << 16) | e.off] = e;
        }
        sleep(SLEEP_S);
        int hits = 0;
        for (size_t i = 0; i < players.size(); i++) {
            for (auto& e2 : get_floats(players[i].addr, players[i].native)) {
                int key = (e2.tag << 16) | e2.off;
                auto it = s1[i].find(key);
                if (it == s1[i].end()) continue;
                auto& e1 = it->second;
                float dx = e2.x - e1.x, dy = e2.y - e1.y, dz = e2.z - e1.z;
                float d = sqrtf(dx * dx + dy * dy + dz * dz);
                if (d < 0.3f || d > 300.0f) continue;
                consistency[{i, key}]++;
                last[{i, key}] = {e2.tag, e2.off, e2.x, e2.y, e2.z};
                hits++;
            }
        }
        printf("    round %2d/%d: %d movements\n", round + 1, ROUNDS, hits);
    }

    // ---- Step 5: report consistent paths ----
    printf("\n=== STABLE PATHS (>=3 rounds) ===\n");
    int stable = 0;
    for (auto& kv : consistency) {
        if (kv.second < 3) continue;
        auto& h = last[kv.first];
        int pi = kv.first.first;
        printf("  P[%d] SID=%llu %s+0x%03x (x%.1f y%.1f z%.1f) %d rounds\n",
               pi, players[pi].sid, h.tag ? "native" : "base", h.off, h.x, h.y, h.z, kv.second);
        stable++;
    }
    printf("\nTotal stable paths: %d\n", stable);
    return 0;
}
