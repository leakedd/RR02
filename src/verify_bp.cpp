// ============================================================================
// RR02/verify_bp.cpp — Verify found BasePlayer objects
// Vtable=0x1279db300, SID=+0x630
// Check: PM pointer, name, flags, transform
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
static float rf(uint64_t a) { return rm<float>(a); }
static bool vptr(uint64_t p) { return p > 0x100000ULL && p < 0x800000000000ULL; }

static std::string read_il2cpp_str(uint64_t field_addr) {
    uint64_t str = r64(field_addr);
    if (!vptr(str)) return "";
    uint32_t len = r32(str + 0x10);
    if (len == 0 || len > 64) return "";
    std::string out;
    for (uint32_t i = 0; i < len && i < 63; i++) {
        uint16_t c = rm<uint16_t>(str + 0x14 + i * 2);
        if (c == 0) break;
        if (c > 31 && c < 127) out += (char)c;
        else out += '?';
    }
    return out;
}

static pid_t find_rust() {
    pid_t pids[4096]; int n = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    for (int i = 0; i < n / (int)sizeof(pid_t); i++) {
        char path[1024]; if (proc_pidpath(pids[i], path, sizeof(path)) > 0 && strstr(path, "RustClient")) return pids[i];
    }
    return -1;
}

static const uint64_t VTABLE = 0x1279db300;
static const int SID_OFFSET = 0x630;
static const uint64_t SID_MIN = 76561198000000000ULL;
static const uint64_t SID_MAX = 76561200000000000ULL;

struct Rg { uint64_t start, end; uint32_t prot; };

int main() {
    printf("=== RR02 Verify BP ===\n");
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

    // Show first 20
    printf("%-20s %-16s %-10s %-10s %-12s\n", "Addr", "SID", "PM(4b8)", "PM(530)", "Name(2b0)");
    printf("%-20s %-16s %-10s %-10s %-12s\n", "----", "---", "------", "------", "--------");
    for (size_t i = 0; i < std::min((size_t)20, unique.size()); i++) {
        auto& bp = unique[i];
        uint64_t pm4b8 = r64(bp.addr + 0x4b8);
        uint64_t pm530 = r64(bp.addr + 0x530);
        std::string name = read_il2cpp_str(bp.addr + 0x2b0);
        printf("0x%-18llx %-16llu %-10s %-10s %-12s\n",
               bp.addr, bp.sid % 100000,
               vptr(pm4b8) ? "OK" : "BAD",
               vptr(pm530) ? "OK" : "BAD",
               name.c_str());
    }

    // Now try offsets from UC post:
    // BasePlayer offsets: PM=0x4b8, NAME=0x2b0, FLAGS=0x598
    // PlayerModel: POS=0x1E8, VEL=0x1F4
    printf("\n=== Testing UC offsets ===\n");
    int pm_ok = 0, pos_ok = 0, name_ok = 0;
    for (auto& bp : unique) {
        uint64_t pm = r64(bp.addr + 0x4b8);
        if (!vptr(pm)) { pm = r64(bp.addr + 0x530); }
        if (vptr(pm)) {
            pm_ok++;
            float px = rf(pm + 0x1E8);
            float py = rf(pm + 0x1E8 + 4);
            float pz = rf(pm + 0x1E8 + 8);
            if (std::isfinite(px) && std::isfinite(py) && std::isfinite(pz) &&
                px > -5000 && px < 5000 && pz > -5000 && pz < 5000 &&
                py > -200 && py < 2000) {
                pos_ok++;
            }
        }
        std::string n = read_il2cpp_str(bp.addr + 0x2b0);
        if (!n.empty() && n.size() > 1 && n.find(".prefab") == std::string::npos) name_ok++;
    }
    printf("PM valid:  %d/%zu\n", pm_ok, unique.size());
    printf("Pos valid: %d/%zu\n", pos_ok, unique.size());
    printf("Name valid: %d/%zu\n", name_ok, unique.size());

    // Also try scanning for the correct PM and name offsets
    // by checking uniqueness of pointers per SID
    printf("\n=== Scanning for correct PM offset ===\n");
    for (int off = 0x100; off < 0x800; off += 8) {
        int unique_pm = 0, valid_ptr = 0;
        std::vector<uint64_t> seen;
        for (auto& bp : unique) {
            uint64_t p = r64(bp.addr + off);
            if (!vptr(p)) continue;
            valid_ptr++;
            bool dup = false;
            for (auto s : seen) { if (s == p) { dup = true; break; } }
            if (!dup) { seen.push_back(p); unique_pm++; }
        }
        if (unique_pm >= 5 && unique_pm == valid_ptr) {
            printf("  +0x%03x: %d unique PM out of %d valid pointers\n", off, unique_pm, valid_ptr);
        }
    }

    return 0;
}