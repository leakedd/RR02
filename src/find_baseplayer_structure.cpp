// RR02/find_baseplayer_structure.cpp
// Automatically discovers the BasePlayer vtable and userID offset on macOS ARM64
// By finding all SteamIDs in heap and grouping by (offset_to_vtable, vtable_address)

#include <cstdio>
#include <cstdint>
#include <cmath>
#include <vector>
#include <map>
#include <set>
#include <algorithm>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>

static task_t g_task;
static bool read_mem(uint64_t addr, void* buf, size_t size) {
    vm_size_t got = 0;
    return vm_read_overwrite(g_task, (vm_address_t)addr, size, (vm_address_t)buf, &got) == KERN_SUCCESS && got == size;
}

template<typename T> static T rm(uint64_t addr) {
    T val{};
    read_mem(addr, &val, sizeof(val));
    return val;
}

static bool is_valid_ptr(uint64_t p) {
    return p > 0x100000ULL && p < 0x800000000000ULL;
}

static bool is_steam_id(uint64_t sid) {
    return sid >= 76561197900000000ULL && sid < 76561300000000000ULL;
}

static pid_t find_rust_pid() {
    pid_t pids[4096];
    int n = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    for (int i = 0; i < n / (int)sizeof(pid_t); i++) {
        char path[1024];
        if (proc_pidpath(pids[i], path, sizeof(path)) > 0 && strstr(path, "Rust")) {
            return pids[i];
        }
    }
    return -1;
}

struct SteamIdHit {
    uint64_t addr;
    uint64_t sid;
};

int main() {
    printf("=== BasePlayer Auto-Discovery (macOS ARM64) ===\n");
    pid_t pid = find_rust_pid();
    if (pid < 0) {
        printf("[!] Rust process not found!\n");
        return 1;
    }
    printf("[+] Found Rust PID: %d\n", pid);

    if (task_for_pid(mach_task_self(), pid, &g_task) != KERN_SUCCESS) {
        printf("[!] task_for_pid failed. Run with sudo!\n");
        return 1;
    }

    // Enumerate readable + writable memory regions
    struct Region { uint64_t start, end; };
    std::vector<Region> regions;
    mach_vm_address_t addr = 0;
    mach_vm_size_t sz = 0;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt;
    mach_port_t obj;

    while (true) {
        cnt = VM_REGION_BASIC_INFO_COUNT_64;
        if (mach_vm_region(g_task, &addr, &sz, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &cnt, &obj) != KERN_SUCCESS) break;
        if ((info.protection & VM_PROT_READ) && (info.protection & VM_PROT_WRITE) && sz <= 128 * 1024 * 1024) {
            regions.push_back({addr, addr + sz});
        }
        addr += sz;
        if (addr == 0) break;
    }
    printf("[+] Enumerated %zu heap regions\n", regions.size());

    // Scan for all SteamIDs
    std::vector<SteamIdHit> sid_hits;
    static uint8_t chunk_buf[8 * 1024 * 1024];

    for (const auto& rg : regions) {
        for (uint64_t off = 0; off < (rg.end - rg.start); off += sizeof(chunk_buf)) {
            uint64_t read_sz = std::min((uint64_t)sizeof(chunk_buf), (rg.end - rg.start - off));
            if (!read_mem(rg.start + off, chunk_buf, read_sz)) break;

            for (size_t i = 0; i + 8 <= read_sz; i += 8) {
                uint64_t val = *reinterpret_cast<uint64_t*>(&chunk_buf[i]);
                if (is_steam_id(val)) {
                    sid_hits.push_back({rg.start + off + i, val});
                }
            }
        }
    }
    printf("[+] Found %zu total SteamID occurrences in heap\n", sid_hits.size());

    if (sid_hits.empty()) {
        printf("[!] No SteamIDs found in memory!\n");
        return 1;
    }

    // Now for each SteamID, look backwards up to 0x800 bytes for a potential object vtable
    // Structure candidate: BasePlayer_addr = (sid_addr - offset)
    // where BasePlayer_addr -> vtable (a valid pointer)
    
    // Map: (offset_from_object_start_to_sid, vtable) -> set of SIDs
    std::map<std::pair<int, uint64_t>, std::set<uint64_t>> candidates;

    for (const auto& hit : sid_hits) {
        for (int sid_offset = 0x10; sid_offset <= 0x800; sid_offset += 8) {
            uint64_t potential_obj = hit.addr - sid_offset;
            uint64_t vtable = rm<uint64_t>(potential_obj);
            if (is_valid_ptr(vtable)) {
                candidates[{sid_offset, vtable}].insert(hit.sid);
            }
        }
    }

    // Rank candidates by unique SIDs count
    struct CandidateRank {
        int sid_offset;
        uint64_t vtable;
        size_t unique_sids;
    };
    std::vector<CandidateRank> ranked;
    for (const auto& kv : candidates) {
        ranked.push_back({kv.first.first, kv.first.second, kv.second.size()});
    }

    std::sort(ranked.begin(), ranked.end(), [](const CandidateRank& a, const CandidateRank& b) {
        return a.unique_sids > b.unique_sids;
    });

    printf("\n=== TOP BASEPLAYER STRUCTURE CANDIDATES ===\n");
    printf("%-10s %-18s %-12s\n", "SID Offset", "VTable/Klass", "Unique SIDs");
    printf("-------------------------------------------\n");

    for (size_t i = 0; i < std::min((size_t)15, ranked.size()); i++) {
        printf("0x%-8x 0x%-16llx %-12zu\n", ranked[i].sid_offset, ranked[i].vtable, ranked[i].unique_sids);
    }

    if (ranked.empty() || ranked[0].unique_sids < 2) {
        printf("[!] Could not confidently identify BasePlayer layout\n");
        return 1;
    }

    int best_sid_offset = ranked[0].sid_offset;
    uint64_t best_vtable = ranked[0].vtable;
    printf("\n[✓] WINNER: VTable = 0x%llx, userID offset = 0x%x (%zu unique players)\n",
           best_vtable, best_sid_offset, ranked[0].unique_sids);

    // Collect all unique BasePlayer objects matching this winning layout
    std::map<uint64_t, uint64_t> player_objects; // sid -> baseplayer_addr
    for (const auto& hit : sid_hits) {
        uint64_t potential_obj = hit.addr - best_sid_offset;
        if (rm<uint64_t>(potential_obj) == best_vtable) {
            player_objects[hit.sid] = potential_obj;
        }
    }

    printf("\n=== DISCOVERED PLAYERS (%zu active) ===\n", player_objects.size());
    for (const auto& kv : player_objects) {
        uint64_t sid = kv.first;
        uint64_t bp_addr = kv.second;

        // Scan the BasePlayer object (0x000 to 0x800) for valid pointers to PlayerModel or Transform
        printf("Player SID: %llu @ 0x%llx\n", sid, bp_addr);

        // Print valid pointers in this BasePlayer object
        for (int off = 0x10; off < 0x800; off += 8) {
            uint64_t ptr = rm<uint64_t>(bp_addr + off);
            if (is_valid_ptr(ptr)) {
                // Read first qword of target
                uint64_t target_vtable = rm<uint64_t>(ptr);
                if (is_valid_ptr(target_vtable)) {
                    printf("   +0x%03x -> Ptr 0x%llx (target vtable: 0x%llx)\n", off, ptr, target_vtable);
                }
            }
        }
        break; // Inspect first player in detail
    }

    return 0;
}
