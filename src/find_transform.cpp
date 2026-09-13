// ============================================================================
// RR02/find_transform.cpp — Find Unity Transform in BasePlayer memory
// Strategy: Test every pointer in BasePlayer (0x000-0x800) to see if it's
// a Unity Transform. A valid Transform has:
//   - AccessReadOnly struct at some offset (x86: +0x38, ARM64: +0x40?)
//   - AccessReadOnly.TransformData pointer → TransformData struct
//   - TransformData.TransformArray pointer → array of Matrix34 (0x30 bytes each)
//   - TransformData.TransformIndecies pointer → array of int32 (parent indices)
//   - Index field at some offset (x86: +0x40, ARM64: +0x48?)
//
// Compile: c++ -O2 -std=c++17 -o find_transform find_transform.cpp
// Run: echo PASSWORD | sudo -S ./find_transform
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
static uint32_t r32(uint64_t a) { return rm<uint32_t>(a); }
static int32_t  ri32(uint64_t a) { return rm<int32_t>(a); }
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

// Try to read position using UC Transform algorithm with given offsets
static bool try_read_pos(uint64_t transform, int access_off, int index_off,
                         float& out_x, float& out_y, float& out_z) {
    uint64_t access = r64(transform + access_off);
    if (!vptr(access)) return false;

    uint64_t tdata = r64(access + 0x18);
    if (!vptr(tdata)) return false;

    uint32_t index = r32(transform + index_off);
    if (index > 10000) return false;

    // Read TransformArray and TransformIndecies pointers
    uint64_t arr = r64(tdata + 0x00);  // TransformArray
    uint64_t idx = r64(tdata + 0x08);  // TransformIndecies
    if (!vptr(arr) || !vptr(idx)) return false;

    // Read initial Matrix34 at index
    // Matrix34 = { Vec1: __m128, Vec2: __m128, Vec3: __m128 } = 48 bytes
    // Position is in Vec1 (first 16 bytes = 4 floats, we want first 3)
    float pos[3];
    if (!read_mem(arr + 0x30 * index, pos, 12)) return false;

    // Check if position is plausible
    if (!std::isfinite(pos[0]) || !std::isfinite(pos[1]) || !std::isfinite(pos[2]))
        return false;
    if (pos[0] < -5000 || pos[0] > 5000) return false;
    if (pos[1] < -200 || pos[1] > 2000) return false;
    if (pos[2] < -5000 || pos[2] > 5000) return false;

    out_x = pos[0];
    out_y = pos[1];
    out_z = pos[2];

    // Now walk the parent chain
    int32_t parent_idx = ri32(idx + 4 * index);
    int safety = 0;
    while (parent_idx >= 0 && safety++ < 200) {
        float parent_pos[3];
        if (!read_mem(arr + 0x30 * parent_idx, parent_pos, 12)) break;

        // For now, just add parent position (simplified - real UC does matrix multiply)
        out_x += parent_pos[0];
        out_y += parent_pos[1];
        out_z += parent_pos[2];

        parent_idx = ri32(idx + 4 * parent_idx);
    }

    return true;
}

int main() {
    printf("=== RR02 Find Transform ===\n");
    printf("Searching for Unity Transform in BasePlayer...\n\n");

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
    std::vector<BP> unique;
    for (auto& b : bps) {
        bool found = false;
        for (auto& u : unique) if (u.sid == b.sid) { found = true; break; }
        if (!found) unique.push_back(b);
    }
    printf("[+] %zu unique BasePlayers\n\n", unique.size());

    if (unique.empty()) {
        printf("[!] No BasePlayers found\n");
        return 1;
    }

    // Test each offset for Transform
    struct Candidate {
        int bp_offset;
        int access_offset;
        int index_offset;
        int valid_count;
        float sample_x, sample_y, sample_z;
    };
    std::vector<Candidate> candidates;

    printf("Testing BasePlayer offsets 0x000-0x800 for Unity Transform...\n");
    fflush(stdout);

    for (int bp_off = 0x00; bp_off < 0x800; bp_off += 8) {
        int valid = 0;
        float sx = 0, sy = 0, sz = 0;

        // Try different AccessReadOnly and Index offsets (ARM64 alignment)
        for (int access_off = 0x38; access_off <= 0x48; access_off += 8) {
            for (int index_off = 0x40; index_off <= 0x50; index_off += 8) {
                int local_valid = 0;
                for (auto& bp : unique) {
                    uint64_t transform = r64(bp.addr + bp_off);
                    if (!vptr(transform)) continue;

                    float px, py, pz;
                    if (try_read_pos(transform, access_off, index_off, px, py, pz)) {
                        local_valid++;
                        if (local_valid == 1) { sx = px; sy = py; sz = pz; }
                    }
                }
                if (local_valid > valid) {
                    valid = local_valid;
                    candidates.push_back({bp_off, access_off, index_off, valid, sx, sy, sz});
                }
            }
        }
    }

    // Sort by valid_count descending
    std::sort(candidates.begin(), candidates.end(), [](const Candidate& a, const Candidate& b) {
        return a.valid_count > b.valid_count;
    });

    printf("\n=== Top Transform Candidates ===\n");
    printf("%-10s %-10s %-10s %-8s %-24s\n", "BP_Off", "Acc_Off", "Idx_Off", "Valid", "Sample Pos");
    printf("%-10s %-10s %-10s %-8s %-24s\n", "------", "-------", "-------", "-----", "----------");

    for (size_t i = 0; i < std::min((size_t)20, candidates.size()); i++) {
        auto& c = candidates[i];
        printf("0x%03x     0x%02x       0x%02x       %-8d (%.1f, %.1f, %.1f)\n",
               c.bp_offset, c.access_offset, c.index_offset, c.valid_count,
               c.sample_x, c.sample_y, c.sample_z);
    }

    if (candidates.empty()) {
        printf("\n[!] No valid Transform found\n");
    } else {
        printf("\n[✓] Best: BP+0x%x, Transform+0x%x (Access), Transform+0x%x (Index)\n",
               candidates[0].bp_offset, candidates[0].access_offset, candidates[0].index_offset);
        printf("    %d/%zu players have valid position\n", candidates[0].valid_count, unique.size());
    }

    return 0;
}