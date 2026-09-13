// ============================================================================
// RR02/resolve_offsets.cpp — With the real vtable (0x141dcf380) and SID offset
// (+0x130), find the remaining offsets: name, health, position, flags
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
static uint32_t r32(uint64_t a) { return rm<uint32_t>(a); }
static float    rf (uint64_t a) { return rm<float>(a); }
static bool vptr(uint64_t p) { return p > 0x100000ULL && p < 0x800000000000ULL; }

static std::string read_il2cpp_str(uint64_t field_addr) {
    uint64_t str = r64(field_addr);
    if (!vptr(str)) return "";
    uint32_t len = r32(str + 0x10);
    if (len == 0 || len > 64) return "";
    std::string out;
    bool in_tag = false;
    for (uint32_t i = 0; i < len && i < 63; i++) {
        uint16_t c = rm<uint16_t>(str + 0x14 + i * 2);
        if (c == 0) break;
        if (c == '<') { in_tag = true; continue; }
        if (c == '>') { in_tag = false; continue; }
        if (in_tag) continue;
        out += (c > 31 && c < 127) ? (char)c : '?';
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

static const uint64_t VTABLE = 0x141dcf380;
static const int SID_OFFSET = 0x130;
static const uint64_t SID_MIN = 76561198000000000ULL;
static const uint64_t SID_MAX = 76561200000000000ULL;

struct Rg { uint64_t start, end; uint32_t prot; };
static std::vector<Rg> g_regions;

int main() {
    printf("=== RR02 Resolve Offsets ===\n");
    pid_t pid = find_rust();
    if (pid < 0) { printf("[!] Rust not found\n"); return 1; }
    if (task_for_pid(mach_task_self(), pid, &g_task) != KERN_SUCCESS) {
        printf("[!] task_for_pid failed\n"); return 1;
    }

    // Get writable regions
    mach_vm_address_t addr = 0; mach_vm_size_t sz; vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt; mach_port_t obj;
    while (true) {
        cnt = VM_REGION_BASIC_INFO_COUNT_64;
        if (mach_vm_region(g_task, &addr, &sz, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &cnt, &obj) != KERN_SUCCESS) break;
        if ((info.protection & VM_PROT_READ) && (info.protection & 2))
            g_regions.push_back({addr, addr + sz, (uint32_t)info.protection});
        addr += sz;
    }

    // Find BasePlayer objects: scan for vtable at offset 0 + valid SID at +0x130
    const size_t CHUNK = 8 * 1024 * 1024;
    static uint8_t buf[8 * 1024 * 1024];
    std::vector<uint64_t> objects;

    for (auto& rg : g_regions) {
        if (rg.end - rg.start > 256 * 1024 * 1024) continue;
        for (uint64_t off = 0; off < rg.end - rg.start; off += CHUNK) {
            uint64_t ch = std::min((uint64_t)CHUNK, rg.end - rg.start - off);
            mach_vm_size_t got = 0;
            if (mach_vm_read_overwrite(g_task, rg.start + off, ch, (vm_address_t)buf, &got) != KERN_SUCCESS) break;
            for (size_t i = 0; i + 8 <= got; i += 8) {
                uint64_t v; memcpy(&v, buf + i, 8);
                if (v == VTABLE) {
                    uint64_t obj = rg.start + off + i;
                    // Verify SID
                    uint64_t sid = r64(obj + SID_OFFSET);
                    if (sid >= SID_MIN && sid < SID_MAX) {
                        objects.push_back(obj);
                    }
                }
            }
        }
    }

    // Deduplicate by SID
    std::unordered_map<uint64_t, uint64_t> by_sid; // sid → obj (keep first)
    for (auto obj : objects) {
        uint64_t sid = r64(obj + SID_OFFSET);
        if (!by_sid.count(sid)) by_sid[sid] = obj;
    }
    printf("[+] %zu unique players (from %zu objects)\n", by_sid.size(), objects.size());

    // Now probe offsets 0x000-0x800 for each unique player
    // Find: name, health, flags, playerModel

    // NAME: pointer to Il2CppString with readable content (2-40 chars, not a path)
    std::unordered_map<int, int> name_hits;
    // HEALTH: float 1.0-200.0, should vary between players
    std::unordered_map<int, int> hp_hits;
    // FLAGS: uint32 with small value (PlayerFlags: 0=alive, 0x10=sleeping, 0x100=connected, 0x40=wounded)
    std::unordered_map<int, std::vector<uint32_t>> flag_values;
    // PM: pointer to object with bone transforms
    std::unordered_map<int, int> pm_hits;

    int probe = 0;
    for (auto& [sid, obj] : by_sid) {
        probe++;
        if (probe > 200) break;
        uint8_t obuf[0x800];
        if (!read_mem(obj, obuf, 0x800)) continue;

        // Name
        for (int off = 0; off + 8 <= 0x800; off += 8) {
            uint64_t p; memcpy(&p, obuf + off, 8);
            if (!vptr(p)) continue;
            std::string s = read_il2cpp_str(obj + off);
            if (s.size() >= 2 && s.size() <= 40 &&
                s.find(".prefab") == std::string::npos &&
                s.find("UnityEngine") == std::string::npos &&
                s.find("assets/") == std::string::npos &&
                s[0] != '_') {
                name_hits[off]++;
            }
        }

        // Health
        for (int off = 0; off + 4 <= 0x800; off += 4) {
            float h; memcpy(&h, obuf + off, 4);
            if (std::isfinite(h) && h >= 1.0f && h <= 200.0f) hp_hits[off]++;
        }

        // Flags: look for uint32 in plausible range
        for (int off = 0; off + 4 <= 0x800; off += 4) {
            uint32_t f; memcpy(&f, obuf + off, 4);
            if (f <= 0xFFFF) { // PlayerFlags should be small
                flag_values[off].push_back(f);
            }
        }

        // PlayerModel
        for (int off = 0; off + 8 <= 0x800; off += 8) {
            uint64_t pm; memcpy(&pm, obuf + off, 8);
            if (!vptr(pm) || pm == VTABLE) continue;
            // Check if it has bone transforms
            uint64_t t = r64(pm + 0x28);
            if (vptr(t)) {
                uint64_t native = r64(t + 0x10);
                if (vptr(native)) pm_hits[off]++;
            }
        }
    }

    // Print best name offset
    printf("\n=== Name Offset ===\n");
    std::vector<std::pair<int,int>> sn;
    for (auto& [o,c] : name_hits) sn.push_back({c,o});
    std::sort(sn.rbegin(), sn.rend());
    for (int i = 0; i < std::min((size_t)5, sn.size()); i++) {
        printf("  +0x%x: %d hits", sn[i].second, sn[i].first);
        if (i == 0) {
            // Show sample names
            printf(" → ");
            int shown = 0;
            for (auto& [sid, obj] : by_sid) {
                if (shown >= 5) break;
                std::string s = read_il2cpp_str(obj + sn[i].second);
                if (!s.empty()) { printf("\"%s\" ", s.c_str()); shown++; }
            }
        }
        printf("\n");
    }

    printf("\n=== Health Offset ===\n");
    sn.clear();
    for (auto& [o,c] : hp_hits) sn.push_back({c,o});
    std::sort(sn.rbegin(), sn.rend());
    for (int i = 0; i < std::min((size_t)5, sn.size()); i++) {
        // Need at least 30% coverage to be plausible (not every float is health)
        if (sn[i].first < probe * 0.3) break;
        printf("  +0x%x: %d/%d hits", sn[i].second, sn[i].first, probe);
        if (i == 0) {
            printf(" → ");
            for (auto& [sid, obj] : by_sid) {
                float h = rf(obj + sn[i].second);
                if (std::isfinite(h) && h > 0 && h <= 200) printf("%.0f ", h);
            }
        }
        printf("\n");
    }

    printf("\n=== PlayerModel Offset ===\n");
    sn.clear();
    for (auto& [o,c] : pm_hits) sn.push_back({c,o});
    std::sort(sn.rbegin(), sn.rend());
    for (int i = 0; i < std::min((size_t)5, sn.size()); i++) {
        if (sn[i].first < 2) break;
        printf("  +0x%x: %d hits\n", sn[i].second, sn[i].first);
    }

    // Try reading position for a player
    printf("\n=== Position Test ===\n");
    if (!sn.empty()) {
        int pm_off = sn[0].second;
        printf("Using PM offset +0x%x\n", pm_off);
        int tested = 0;
        for (auto& [sid, obj] : by_sid) {
            if (tested >= 10) break;
            uint64_t pm = r64(obj + pm_off);
            if (!vptr(pm)) continue;
            for (uint32_t bo : {0x28u, 0x30u, 0x38u, 0x40u, 0x48u}) {
                uint64_t m = r64(pm + bo);
                if (!vptr(m)) continue;
                uint64_t n = r64(m + 0x10);
                if (!vptr(n)) continue;
                for (int64_t s = -0x400; s <= 0x400; s += 4) {
                    uint64_t a = (uint64_t)((int64_t)n + s);
                    float x = rf(a), y = rf(a+4), z = rf(a+8);
                    if (!std::isfinite(x) || !std::isfinite(y) || !std::isfinite(z)) continue;
                    if (x < -5000 || x > 5000 || z < -5000 || z > 5000) continue;
                    if (y < -200 || y > 2000) continue;
                    if (sqrtf(x*x+z*z) < 10) continue;
                    printf("  SID=%llu pos=(%.1f,%.1f,%.1f) via bone+0x%x\n", sid, x, y, z, bo);
                    tested++;
                    break;
                }
                if (tested >= 10) break;
            }
        }
    }

    return 0;
}