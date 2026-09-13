// RR02/analyze_targets.cpp
// Analyzes the target pointers inside the 280 player entries
// to find which target contains live positions (X, Y, Z floats)

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

static bool is_coord(float f) {
    return std::isfinite(f) && f > -5000.0f && f < 5000.0f && fabsf(f) > 0.01f;
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

struct PlayerEntry {
    uint64_t entry_addr;
    uint64_t sid;
};

int main() {
    printf("=== RR02 Target Analyzer ===\n");
    pid_t pid = find_rust_pid();
    if (pid < 0 || task_for_pid(mach_task_self(), pid, &g_task) != KERN_SUCCESS) {
        printf("[!] Failed to attach to Rust process\n");
        return 1;
    }

    // Enumerate heap regions
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

    const uint64_t TARGET_VTABLE = 0x3427138e0;
    const int SID_OFFSET = 0x10;

    std::vector<PlayerEntry> players;
    static uint8_t chunk_buf[8 * 1024 * 1024];

    for (const auto& rg : regions) {
        for (uint64_t off = 0; off < (rg.end - rg.start); off += sizeof(chunk_buf)) {
            uint64_t read_sz = std::min((uint64_t)sizeof(chunk_buf), (rg.end - rg.start - off));
            if (!read_mem(rg.start + off, chunk_buf, read_sz)) break;

            for (size_t i = 0; i + 8 <= read_sz; i += 8) {
                if (*reinterpret_cast<uint64_t*>(&chunk_buf[i]) == TARGET_VTABLE) {
                    uint64_t entry_addr = rg.start + off + i;
                    uint64_t sid = rm<uint64_t>(entry_addr + SID_OFFSET);
                    if (is_steam_id(sid)) {
                        // Dedup
                        bool dup = false;
                        for (const auto& p : players) if (p.sid == sid) { dup = true; break; }
                        if (!dup) players.push_back({entry_addr, sid});
                    }
                }
            }
        }
    }

    printf("[+] Found %zu unique player entries\n", players.size());

    // Test each relative offset from entry_addr: 
    // Case A: Offset directly inside entry_addr (e.g. entry_addr + offset)
    // Case B: Offset inside target pointer (e.g. rm<uint64_t>(entry_addr + ptr_offset) + float_offset)

    printf("\n=== Scanning direct floats inside entry_addr ===\n");
    for (int off = 0x00; off < 0x800; off += 4) {
        int valid_coords = 0;
        for (const auto& p : players) {
            float x = rm<float>(p.entry_addr + off);
            float y = rm<float>(p.entry_addr + off + 4);
            float z = rm<float>(p.entry_addr + off + 8);
            if (is_coord(x) && is_coord(y) && is_coord(z)) valid_coords++;
        }
        if (valid_coords >= 5) {
            printf("Direct Float @ entry + 0x%03x: %d/%zu players have valid (X,Y,Z)\n", off, valid_coords, players.size());
            for (size_t i = 0; i < std::min((size_t)3, players.size()); i++) {
                float x = rm<float>(players[i].entry_addr + off);
                float y = rm<float>(players[i].entry_addr + off + 4);
                float z = rm<float>(players[i].entry_addr + off + 8);
                if (is_coord(x) && is_coord(y) && is_coord(z)) {
                    printf("   SID %llu: (%.1f, %.1f, %.1f)\n", players[i].sid % 100000, x, y, z);
                }
            }
        }
    }

    printf("\n=== Scanning indirect floats (via pointers inside entry_addr) ===\n");
    for (int ptr_off = 0x20; ptr_off < 0x800; ptr_off += 8) {
        // Collect pointers
        std::map<int, int> float_off_counts;
        for (const auto& p : players) {
            uint64_t ptr = rm<uint64_t>(p.entry_addr + ptr_off);
            if (!is_valid_ptr(ptr)) continue;
            for (int f_off = 0x00; f_off < 0x400; f_off += 4) {
                float x = rm<float>(ptr + f_off);
                float y = rm<float>(ptr + f_off + 4);
                float z = rm<float>(ptr + f_off + 8);
                if (is_coord(x) && is_coord(y) && is_coord(z)) {
                    float_off_counts[f_off]++;
                }
            }
        }
        for (const auto& kv : float_off_counts) {
            if (kv.second >= 5) {
                printf("Indirect Float @ (entry + 0x%03x) -> (ptr + 0x%03x): %d/%zu players\n",
                       ptr_off, kv.first, kv.second, players.size());
                // Print sample
                for (size_t i = 0; i < std::min((size_t)3, players.size()); i++) {
                    uint64_t ptr = rm<uint64_t>(players[i].entry_addr + ptr_off);
                    if (!is_valid_ptr(ptr)) continue;
                    float x = rm<float>(ptr + kv.first);
                    float y = rm<float>(ptr + kv.first + 4);
                    float z = rm<float>(ptr + kv.first + 8);
                    if (is_coord(x) && is_coord(y) && is_coord(z)) {
                        printf("   SID %llu: (%.1f, %.1f, %.1f)\n", players[i].sid % 100000, x, y, z);
                    }
                }
            }
        }
    }

    return 0;
}
