// ============================================================================
// RR02/find_pos_delta2.cpp — Find position offset by comparing full BasePlayer
// memory before/after movement. Scans the ENTIRE 0x800 bytes for changed floats.
// ============================================================================

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>
#include <unordered_map>
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
static const uint64_t SID_MIN = 76561198000000000ULL;
static const uint64_t SID_MAX = 76561200000000000ULL;

struct Rg { uint64_t start, end; uint32_t prot; };

int main() {
    printf("=== RR02 Find Pos Delta v2 ===\n");
    printf("Ce programme scanne TOUS les BasePlayers pour des floats qui changent.\n");
    printf("BOUGE TOI quand le message apparait !\n\n");

    pid_t pid = find_rust();
    if (pid < 0) { printf("[!] Rust not found\n"); return 1; }
    if (task_for_pid(mach_task_self(), pid, &g_task) != KERN_SUCCESS) {
        printf("[!] task_for_pid failed\n"); return 1; }

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

    // Find all BasePlayer objects
    const size_t CHUNK = 8 * 1024 * 1024;
    static uint8_t buf[8 * 1024 * 1024];
    std::vector<uint64_t> objects;

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
                uint64_t obj = rg.start + off + i * 8;
                uint64_t sid = r64(obj + SID_OFFSET);
                if (sid >= SID_MIN && sid < SID_MAX) objects.push_back(obj);
            }
        }
    }

    // Deduplicate by SID
    std::vector<uint64_t> unique;
    for (auto obj : objects) {
        uint64_t sid = r64(obj + SID_OFFSET);
        bool found = false;
        for (auto u : unique) {
            if (r64(u + SID_OFFSET) == sid) { found = true; break; }
        }
        if (!found) unique.push_back(obj);
    }

    printf("[+] %zu unique BasePlayers\n", unique.size());

    // Take snapshot of ALL BasePlayers (0x800 bytes each)
    const int SCAN_SIZE = 0x800;
    int num = std::min((size_t)30, unique.size());

    std::vector<uint8_t> snap1(num * SCAN_SIZE);
    for (int i = 0; i < num; i++) {
        if (!read_mem(unique[i], &snap1[i * SCAN_SIZE], SCAN_SIZE)) {
            memset(&snap1[i * SCAN_SIZE], 0, SCAN_SIZE);
        }
    }

    printf("\n*** BOUGE TOI MAINTENANT ! *** (attente 5 secondes)\n");
    fflush(stdout);
    sleep(5);

    std::vector<uint8_t> snap2(num * SCAN_SIZE);
    for (int i = 0; i < num; i++) {
        if (!read_mem(unique[i], &snap2[i * SCAN_SIZE], SCAN_SIZE)) {
            memset(&snap2[i * SCAN_SIZE], 0, SCAN_SIZE);
        }
    }

    // Find offsets that changed for ANY player
    printf("\n=== Changed floats ===\n");
    struct Change {
        int bp_index;
        uint64_t sid;
        int offset;
        float old_val;
        float new_val;
    };
    std::vector<Change> changes;

    for (int i = 0; i < num; i++) {
        uint64_t sid = r64(unique[i] + SID_OFFSET);
        for (int off = 0; off + 4 <= SCAN_SIZE; off += 4) {
            float f1, f2;
            memcpy(&f1, &snap1[i * SCAN_SIZE + off], 4);
            memcpy(&f2, &snap2[i * SCAN_SIZE + off], 4);
            if (f1 != f2) {
                bool v1 = std::isfinite(f1) && f1 > -5000 && f1 < 5000;
                bool v2 = std::isfinite(f2) && f2 > -5000 && f2 < 5000;
                changes.push_back({i, sid, off, f1, f2});
                printf("  BP[%d] SID=%llu +0x%03x: %.4f -> %.4f%s\n",
                       i, sid, off, f1, f2, (v1 && v2) ? " <-- COORD?" : "");
            }
        }
    }

    printf("\n  Total: %zu changes across %d players\n", changes.size(), num);

    // If we found coordinate-like changes, try to identify which players moved
    if (!changes.empty()) {
        // Group by offset
        std::unordered_map<int, int> offset_counts;
        for (auto& c : changes) offset_counts[c.offset]++;

        printf("\n=== Offsets that changed for multiple players ===\n");
        std::vector<std::pair<int,int>> sorted;
        for (auto& [off, cnt] : offset_counts) sorted.push_back({cnt, off});
        std::sort(sorted.rbegin(), sorted.rend());
        for (auto& [cnt, off] : sorted) {
            if (cnt < 2) break;
            printf("  +0x%03x: changed for %d players\n", off, cnt);
        }
    }

    return 0;
}