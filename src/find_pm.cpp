// ============================================================================
// RR02/find_pm.cpp — Find the real PlayerModel offset
// Strategy: For each unique SteamID, scan offsets 0x000-0x800
// and find pointers that are UNIQUE per SID (different for each player)
// and point to objects with bone transforms
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

static const uint64_t VTABLE = 0x141dcf380;
static const int SID_OFFSET = 0x130;
static const uint64_t SID_MIN = 76561198000000000ULL;
static const uint64_t SID_MAX = 76561200000000000ULL;

struct Rg { uint64_t start, end; uint32_t prot; };

int main() {
    printf("=== RR02 Find PlayerModel Offset ===\n");
    pid_t pid = find_rust();
    if (pid < 0) { printf("[!] Rust not found\n"); return 1; }
    if (task_for_pid(mach_task_self(), pid, &g_task) != KERN_SUCCESS) {
        printf("[!] task_for_pid failed\n"); return 1;
    }

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

    // Find BasePlayer objects
    const size_t CHUNK = 8 * 1024 * 1024;
    static uint8_t buf[8 * 1024 * 1024];

    struct BP { uint64_t addr, sid; };
    std::vector<BP> bps;

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
                if (sid >= SID_MIN && sid < SID_MAX) bps.push_back({bp, sid});
            }
        }
    }

    // Deduplicate by SID
    std::vector<BP> unique_bps;
    for (auto& b : bps) {
        bool found = false;
        for (auto& u : unique_bps) {
            if (u.sid == b.sid) { found = true; break; }
        }
        if (!found) unique_bps.push_back(b);
    }
    printf("[+] %zu unique BasePlayers\n", unique_bps.size());

    // For each offset 0x000-0x800, check if the pointer is unique per SID
    // and points to an object with valid bone transforms
    struct OffsetScore {
        int offset;
        int unique_count;    // how many unique pointer values
        int valid_bone_count; // how many have valid bone transforms
    };

    std::vector<OffsetScore> scores;

    for (int off = 0x10; off < 0x800; off += 8) {
        std::unordered_map<uint64_t, int> ptr_counts; // pointer value → count
        int valid_bones = 0;
        int total = 0;

        for (auto& bp : unique_bps) {
            uint64_t p = r64(bp.addr + off);
            if (!vptr(p) || p == VTABLE) continue;
            total++;
            ptr_counts[p]++;

            // Check if this pointer has bone transforms
            // Try: p+0x28 → managed Transform → +0x10 → native
            uint64_t bone = r64(p + 0x28);
            if (vptr(bone)) {
                uint64_t native = r64(bone + 0x10);
                if (vptr(native)) valid_bones++;
            }
            // Also try p+0x30, p+0x38
            bone = r64(p + 0x30);
            if (vptr(bone)) {
                uint64_t native = r64(bone + 0x10);
                if (vptr(native)) valid_bones++;
            }
            bone = r64(p + 0x38);
            if (vptr(bone)) {
                uint64_t native = r64(bone + 0x10);
                if (vptr(native)) valid_bones++;
            }
        }

        // Count how many unique pointer values there are
        int unique = 0;
        for (auto& [ptr, cnt] : ptr_counts) {
            if (cnt == 1) unique++;  // unique = appears only once
        }

        // Good PM offset: high unique count + high valid bone count
        if (valid_bones >= 5 && unique >= 5) {
            scores.push_back({off, unique, valid_bones});
        }
    }

    // Sort by (unique_count * valid_bone_count) descending
    std::sort(scores.begin(), scores.end(), [](const OffsetScore& a, const OffsetScore& b) {
        return a.unique_count * a.valid_bone_count > b.unique_count * b.valid_bone_count;
    });

    printf("\n=== Top PlayerModel offset candidates ===\n");
    for (int i = 0; i < std::min((size_t)20, scores.size()); i++) {
        auto& s = scores[i];
        printf("  +0x%03x: unique=%d valid_bones=%d score=%d\n",
               s.offset, s.unique_count, s.valid_bone_count,
               s.unique_count * s.valid_bone_count);
    }

    // For the top 3, show the native ptrs and check if they're different
    if (!scores.empty()) {
        int best = scores[0].offset;
        printf("\n=== Best offset +0x%x — detailed ===\n", best);
        for (auto& bp : unique_bps) {
            uint64_t pm = r64(bp.addr + best);
            if (!vptr(pm)) continue;
            uint64_t native0x28 = 0, native0x30 = 0, native0x38 = 0;
            uint64_t b = r64(pm + 0x28);
            if (vptr(b)) { native0x28 = r64(b + 0x10); }
            b = r64(pm + 0x30);
            if (vptr(b)) { native0x30 = r64(b + 0x10); }
            b = r64(pm + 0x38);
            if (vptr(b)) { native0x38 = r64(b + 0x10); }
            printf("  SID=%llu PM=0x%llx native(28)=0x%llx native(30)=0x%llx native(38)=0x%llx\n",
                   bp.sid, pm, native0x28, native0x30, native0x38);
        }
    }

    return 0;
}