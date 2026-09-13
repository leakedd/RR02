// ============================================================================
// RR02/find_pos_delta.cpp — Find the position offset in Unity Transform native
// by comparing memory snapshots before/after player movement.
//
// Strategy:
// 1. Pick a player with a valid PlayerModel
// 2. Dump 0x800 bytes around the native Transform ptr
// 3. Wait 3 seconds (player should move)
// 4. Dump again
// 5. Find which float offsets changed — those are the position fields
//
// Compile: c++ -O2 -std=c++17 -o find_pos_delta find_pos_delta.cpp
// Run: echo PASSWORD | sudo -S ./find_pos_delta
// ============================================================================

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>
#include <string>
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
static float    rf (uint64_t a) { return rm<float>(a); }
static bool vptr(uint64_t p) { return p > 0x100000ULL && p < 0x800000000000ULL; }

static pid_t find_rust() {
    pid_t pids[4096]; int n = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    for (int i = 0; i < n / (int)sizeof(pid_t); i++) {
        char path[1024]; if (proc_pidpath(pids[i], path, sizeof(path)) > 0 && strstr(path, "RustClient")) return pids[i];
    }
    return -1;
}

static const uint64_t VTABLE = 0x141dcf380;
static const int SID_OFFSET = 0x130;
static const int PM_OFFSET = 0x530;
static const uint64_t SID_MIN = 76561198000000000ULL;
static const uint64_t SID_MAX = 76561200000000000ULL;

struct Rg { uint64_t start, end; uint32_t prot; };

int main() {
    printf("=== RR02 Find Pos Delta ===\n");
    printf("Bouge-toi en jeu pendant que ce programme tourne !\n\n");

    pid_t pid = find_rust();
    if (pid < 0) { printf("[!] Rust not found\n"); return 1; }
    if (task_for_pid(mach_task_self(), pid, &g_task) != KERN_SUCCESS) {
        printf("[!] task_for_pid failed\n"); return 1;
    }

    // Get writable regions
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

    // Find BasePlayer objects with valid PlayerModel
    const size_t CHUNK = 8 * 1024 * 1024;
    static uint8_t buf[8 * 1024 * 1024];

    struct Candidate {
        uint64_t bp;     // BasePlayer addr
        uint64_t sid;
        uint64_t pm;     // PlayerModel
        uint64_t native; // native Transform ptr (from bone+0x28 → m_CachedPtr+0x10)
    };

    std::vector<Candidate> candidates;

    for (auto& rg : regions) {
        if (rg.end - rg.start > 256 * 1024 * 1024) continue;
        for (uint64_t off = 0; off < rg.end - rg.start; off += CHUNK) {
            uint64_t ch = std::min((uint64_t)CHUNK, rg.end - rg.start - off);
            mach_vm_size_t got = 0;
            if (mach_vm_read_overwrite(g_task, rg.start + off, ch, (vm_address_t)buf, &got) != KERN_SUCCESS) break;
            size_t n = got / 8;
            for (size_t i = 0; i < n; i++) {
                uint64_t v; memcpy(&v, buf + i * 8, 8);
                if (v != VTABLE) continue;
                uint64_t bp = rg.start + off + i * 8;
                uint64_t sid = r64(bp + SID_OFFSET);
                if (sid < SID_MIN || sid >= SID_MAX) continue;

                uint64_t pm = r64(bp + PM_OFFSET);
                if (!vptr(pm)) continue;

                // Get native transform from bone+0x28
                uint64_t managed = r64(pm + 0x28);
                if (!vptr(managed)) continue;
                uint64_t native = r64(managed + 0x10);
                if (!vptr(native)) continue;

                candidates.push_back({bp, sid, pm, native});
            }
        }
    }

    // Deduplicate by SID (keep first)
        {
            std::vector<Candidate> deduped;
            for (auto& c : candidates) {
                bool found = false;
                for (auto& d : deduped) {
                    if (d.sid == c.sid) { found = true; break; }
                }
                if (!found) deduped.push_back(c);
            }
            candidates = deduped;
        }

    printf("[+] Found %zu candidate players with native Transform\n", candidates.size());

    if (candidates.empty()) {
        printf("[!] No candidates found\n");
        return 1;
    }

    // For each candidate, dump memory around native ptr, wait, dump again, find deltas
    const int SNAPSHOT_SIZE = 0x800;
    const int NUM_CANDIDATES = std::min((size_t)5, candidates.size());

    for (int ci = 0; ci < NUM_CANDIDATES; ci++) {
        auto& c = candidates[ci];
        uint64_t native = c.native;

        printf("\n=== Candidate %d: SID=%llu native=0x%llx ===\n", ci, c.sid, native);

        // Snapshot 1
        uint8_t snap1[SNAPSHOT_SIZE];
        if (!read_mem(native - 0x100, snap1, SNAPSHOT_SIZE)) {
            printf("  Can't read memory around native\n");
            continue;
        }

        printf("  Snapshot 1 taken. BOUGE TOI MAINTENANT ! Attente 5 secondes...\n");
        fflush(stdout);
        sleep(5);

        // Snapshot 2
        uint8_t snap2[SNAPSHOT_SIZE];
        if (!read_mem(native - 0x100, snap2, SNAPSHOT_SIZE)) {
            printf("  Can't read memory for snapshot 2\n");
            continue;
        }

        // Find changed float offsets (within -0x100 to +0x700 from native)
        int changes = 0;
        for (int off = 0; off < SNAPSHOT_SIZE; off += 4) {
            float f1, f2;
            memcpy(&f1, snap1 + off, 4);
            memcpy(&f2, snap2 + off, 4);
            if (f1 != f2) {
                int rel = off - 0x100;  // relative to native ptr
                // Check if both are plausible world coords
                bool valid1 = std::isfinite(f1) && f1 > -5000 && f1 < 5000;
                bool valid2 = std::isfinite(f2) && f2 > -5000 && f2 < 5000;
                printf("  +0x%03x: %.4f -> %.4f%s\n", rel, f1, f2,
                       (valid1 && valid2) ? " <-- WORLD COORD?" : "");
                changes++;
            }
        }

        if (changes == 0) {
            printf("  No changes detected (player didn't move or wrong transform)\n");
        } else {
            printf("  %d offsets changed\n", changes);
        }
    }

    return 0;
}