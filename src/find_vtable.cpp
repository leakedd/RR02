// ============================================================================
// RR02/find_vtable.cpp — Find the REAL vtable used by runtime BasePlayer objects
// Strategy: Scan for SteamIDs (which we know works from recon), then for each
// SteamID candidate, check what pointer is at offset 0 (the vtable).
// The most common vtable among SteamID candidates = real BasePlayer vtable.
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
template<typename T> static T rm(uint64_t a) { T v{}; read_mem(a, &v, sizeof(v)); return v; }
static uint64_t r64(uint64_t a) { return rm<uint64_t>(a); }
static bool vptr(uint64_t p) { return p > 0x100000ULL && p < 0x800000000000ULL; }

static pid_t find_rust() {
    pid_t pids[4096]; int n = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    for (int i = 0; i < n / (int)sizeof(pid_t); i++) {
        char path[1024]; if (proc_pidpath(pids[i], path, sizeof(path)) > 0 && strstr(path, "RustClient")) return pids[i];
    }
    return -1;
}

struct Rg { uint64_t start, end; uint32_t prot; };
static std::vector<Rg> g_regions;

int main() {
    printf("=== RR02 Find Vtable ===\n");
    pid_t pid = find_rust();
    if (pid < 0) { printf("[!] Rust not found\n"); return 1; }
    if (task_for_pid(mach_task_self(), pid, &g_task) != KERN_SUCCESS) {
        printf("[!] task_for_pid failed\n"); return 1;
    }

    // Get writable regions only (where runtime objects live)
    mach_vm_address_t addr = 0; mach_vm_size_t sz; vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt; mach_port_t obj;
    while (true) {
        cnt = VM_REGION_BASIC_INFO_COUNT_64;
        if (mach_vm_region(g_task, &addr, &sz, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &cnt, &obj) != KERN_SUCCESS) break;
        if ((info.protection & VM_PROT_READ) && (info.protection & 2)) // readable + writable = heap
            g_regions.push_back({addr, addr + sz, (uint32_t)info.protection});
        addr += sz;
    }
    printf("[+] %zu writable regions\n", g_regions.size());

    // Scan for SteamIDs, then record the vtable (first 8 bytes of the object)
    // Try: SteamID at various offsets from the start of the object
    // We know SteamID is a uint64 in range [76561198000000000, 76561200000000000)
    const uint64_t SID_MIN = 76561198000000000ULL;
    const uint64_t SID_MAX = 76561200000000000ULL;

    // For each SteamID found in memory, the BasePlayer starts some bytes before it.
    // The vtable is at offset 0 of the BasePlayer.
    // We found SteamID at offset 0x6B8 previously, but it may have changed.
    // Let's scan for SteamIDs and for each one, record the vtable at (sid_addr - offset)
    // for a range of offsets, and find which offset gives a consistent vtable.

    const size_t CHUNK = 8 * 1024 * 1024;
    static uint8_t buf[8 * 1024 * 1024];

    // Collect all SteamID addresses
    std::vector<uint64_t> sid_addrs;
    for (auto& rg : g_regions) {
        if (rg.end - rg.start > 256 * 1024 * 1024) continue;
        for (uint64_t off = 0; off < rg.end - rg.start; off += CHUNK) {
            uint64_t ch = std::min((uint64_t)CHUNK, rg.end - rg.start - off);
            mach_vm_size_t got = 0;
            if (mach_vm_read_overwrite(g_task, rg.start + off, ch, (vm_address_t)buf, &got) != KERN_SUCCESS) break;
            for (size_t i = 0; i + 8 <= got; i += 8) {
                uint64_t v; memcpy(&v, buf + i, 8);
                if (v >= SID_MIN && v < SID_MAX) {
                    sid_addrs.push_back(rg.start + off + i);
                }
            }
        }
    }
    printf("[+] Found %zu SteamID candidates in writable memory\n", sid_addrs.size());

    // For each possible SID offset (0x100-0x800 step 8), count vtable frequency
    // The vtable should be a read-only pointer (in code/data section)
    // and should be the SAME for all real BasePlayer objects
    printf("[*] Scanning for consistent vtable...\n");

    struct VtableHit {
        uint64_t vtable;
        int sid_offset;
        int count;
    };

    std::unordered_map<uint64_t, std::unordered_map<int, int>> vtable_by_offset;

    for (uint64_t sid_addr : sid_addrs) {
        for (int sid_off = 0x100; sid_off <= 0x800; sid_off += 8) {
            if (sid_addr < (uint64_t)sid_off) continue;
            uint64_t obj = sid_addr - sid_off;
            uint64_t vt = r64(obj);
            if (!vptr(vt)) continue;
            // Verify: read SID back
            uint64_t sid_check = r64(obj + sid_off);
            if (sid_check < SID_MIN || sid_check >= SID_MAX) continue;
            // The SID at this offset should match the one we found
            // (it does by construction)
            vtable_by_offset[vt][sid_off]++;
        }
    }

    // Find the vtable+offset pair with highest count
    uint64_t best_vtable = 0;
    int best_sid_offset = 0;
    int best_count = 0;

    for (auto& [vt, offsets] : vtable_by_offset) {
        for (auto& [off, cnt] : offsets) {
            if (cnt > best_count) {
                best_count = cnt;
                best_vtable = vt;
                best_sid_offset = off;
            }
        }
    }

    printf("\n=== RESULTS ===\n");
    printf("Best vtable: 0x%llx at SID offset +0x%x (%d matches)\n",
           best_vtable, best_sid_offset, best_count);

    if (best_count >= 3) {
        printf("\n=== Validated BasePlayers ===\n");
        // Now find all objects with this vtable
        int count = 0;
        for (uint64_t sid_addr : sid_addrs) {
            if (sid_addr < (uint64_t)best_sid_offset) continue;
            uint64_t obj = sid_addr - best_sid_offset;
            uint64_t vt = r64(obj);
            if (vt != best_vtable) continue;
            uint64_t sid = r64(obj + best_sid_offset);
            printf("  [BP] 0x%llx SID=%llu\n", obj, sid);
            count++;
            if (count >= 30) break;
        }
        printf("\n  %d valid BasePlayers\n", count);
    } else {
        printf("\n[!] No consistent vtable found\n");
        // Show top 10
        std::vector<std::pair<int, std::pair<uint64_t,int>>> sorted;
        for (auto& [vt, offsets] : vtable_by_offset)
            for (auto& [off, cnt] : offsets)
                sorted.push_back({cnt, {vt, off}});
        std::sort(sorted.rbegin(), sorted.rend());
        for (int i = 0; i < std::min((size_t)20, sorted.size()); i++) {
            printf("  vtable=0x%llx offset=+0x%x count=%d\n",
                   sorted[i].second.first, sorted[i].second.second, sorted[i].first);
        }
    }

    return 0;
}