// ============================================================================
// RR02/find_class.cpp — Find BasePlayer Il2CppClass via string scan
// Strategy:
// 1. Scan read-only regions for C-string "BasePlayer"
// 2. Find pointers to that string → Il2CppClass->name field
// 3. klass = ptr - 0x10 (name is at +0x10 in Il2CppClass on ARM64)
// 4. Validate klass structure, dump offsets
// 5. Then scan heap: any object where r64(obj) == klass → real BasePlayer
// Compile: c++ -O2 -std=c++17 -o find_class find_class.cpp
// Run: echo PASSWORD | sudo -S ./find_class
// ============================================================================

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>
#include <unordered_map>
#include <unordered_set>
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

template<typename T> static T rm(uint64_t a) {
    T v{}; read_mem(a, &v, sizeof(v)); return v;
}
static uint64_t r64(uint64_t a) { return rm<uint64_t>(a); }
static uint32_t r32(uint64_t a) { return rm<uint32_t>(a); }
static float    rf (uint64_t a) { return rm<float>(a); }

static bool vptr(uint64_t p) { return p > 0x100000ULL && p < 0x800000000000ULL; }

static std::string read_cstr(uint64_t a, size_t max = 256) {
    std::string s;
    char buf[256];
    for (size_t off = 0; off < max; off += 256) {
        size_t chunk = std::min((size_t)256, max - off);
        if (!read_mem(a + off, buf, chunk)) break;
        for (size_t i = 0; i < chunk; i++) {
            if (buf[i] == 0) return s;
            if (buf[i] >= 32 && buf[i] < 127) s += buf[i];
            else return s;
        }
    }
    return s;
}

static std::string read_il2cpp_str(uint64_t field_addr) {
    uint64_t str = r64(field_addr);
    if (!vptr(str)) return "";
    uint32_t len = r32(str + 0x10);
    if (len == 0 || len > 64) return "";
    std::string out;
    for (uint32_t i = 0; i < len && i < 63; i++) {
        uint16_t c = rm<uint16_t>(str + 0x14 + i * 2);
        if (c == 0) break;
        out += (c > 31 && c < 127) ? (char)c : '?';
    }
    return (out.size() >= 2) ? out : "";
}

static pid_t find_rust() {
    pid_t pids[4096];
    int n = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    for (int i = 0; i < n / (int)sizeof(pid_t); i++) {
        char path[1024];
        if (proc_pidpath(pids[i], path, sizeof(path)) > 0 && strstr(path, "RustClient"))
            return pids[i];
    }
    return -1;
}

struct Region { uint64_t start, end; uint32_t prot; uint64_t size() const { return end - start; } };

static std::vector<Region> get_regions() {
    std::vector<Region> regions;
    mach_vm_address_t addr = 0;
    mach_vm_size_t size;
    vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt;
    mach_port_t obj;
    while (true) {
        cnt = VM_REGION_BASIC_INFO_COUNT_64;
        if (mach_vm_region(g_task, &addr, &size, VM_REGION_BASIC_INFO_64,
                           (vm_region_info_t)&info, &cnt, &obj) != KERN_SUCCESS) break;
        if (info.protection & VM_PROT_READ)
            regions.push_back({addr, addr + size, (uint32_t)info.protection});
        addr += size;
    }
    return regions;
}

// Check if address is in any region
static std::vector<Region> g_regions;
static bool in_region(uint64_t a) {
    for (auto& r : g_regions)
        if (a >= r.start && a < r.end) return true;
    return false;
}

// ============================================================================
// Phase 1: Find "BasePlayer" string instances in read-only memory
// ============================================================================
static std::vector<uint64_t> find_string(const char* target) {
    size_t tlen = strlen(target) + 1; // include null terminator
    std::vector<uint64_t> hits;
    const size_t CHUNK = 8 * 1024 * 1024;
    static uint8_t buf[8 * 1024 * 1024];
    int ri = 0;
    for (auto& rg : g_regions) {
        ri++;
        // Only scan non-writable regions (code/rodata) — class names live in __TEXT
        if (rg.prot & 2) continue; // skip writable
        if (rg.size() > 256 * 1024 * 1024) continue;
        for (uint64_t off = 0; off < rg.size(); off += CHUNK) {
            uint64_t chunk = std::min((uint64_t)CHUNK, rg.size() - off);
            mach_vm_size_t got = 0;
            if (mach_vm_read_overwrite(g_task, rg.start + off, chunk,
                                       (vm_address_t)buf, &got) != KERN_SUCCESS) break;
            for (size_t i = 0; i + tlen <= got; i++) {
                if (memcmp(buf + i, target, tlen) == 0) {
                    // Check it's standalone (preceded by 0 or start of region)
                    if (i == 0 || buf[i - 1] == 0) {
                        hits.push_back(rg.start + off + i);
                    }
                }
            }
        }
    }
    return hits;
}

// ============================================================================
// Phase 2: Find pointers to those strings → Il2CppClass candidates
// ============================================================================
static std::vector<uint64_t> find_ptrs_to(uint64_t target_val) {
    std::vector<uint64_t> hits;
    const size_t CHUNK = 8 * 1024 * 1024;
    static uint8_t buf[8 * 1024 * 1024];
    for (auto& rg : g_regions) {
        if (rg.size() > 256 * 1024 * 1024) continue;
        for (uint64_t off = 0; off < rg.size(); off += CHUNK) {
            uint64_t chunk = std::min((uint64_t)CHUNK, rg.size() - off);
            mach_vm_size_t got = 0;
            if (mach_vm_read_overwrite(g_task, rg.start + off, chunk,
                                       (vm_address_t)buf, &got) != KERN_SUCCESS) break;
            size_t n = got / 8;
            for (size_t i = 0; i < n; i++) {
                uint64_t v; memcpy(&v, buf + i * 8, 8);
                if (v == target_val) {
                    hits.push_back(rg.start + off + i * 8);
                }
            }
        }
    }
    return hits;
}

// ============================================================================
// Phase 3: Validate Il2CppClass and extract klass pointer
// On ARM64 IL2CPP, Il2CppClass layout (approximate):
//   +0x00 image
//   +0x08 gc_desc
//   +0x10 name (char*)
//   +0x18 namespaze (char*)
//   +0x20 byval_arg (Il2CppType, 16 bytes)
//   +0x30 this_arg
//   ...
//   +0x88 fields (FieldInfo*)
//   ...
// The first 8 bytes of any IL2CPP object == pointer to its Il2CppClass
// ============================================================================

struct KlassInfo {
    uint64_t klass_addr;
    uint64_t vtable_addr;  // The value that BasePlayer objects will have at +0x00
    std::string namespace_name;
};

int main() {
    printf("=== RR02 Find Class ===\n");

    pid_t pid = find_rust();
    if (pid < 0) { printf("[!] Rust not found\n"); return 1; }
    printf("[+] Rust pid=%d\n", pid);
    if (task_for_pid(mach_task_self(), pid, &g_task) != KERN_SUCCESS) {
        printf("[!] task_for_pid failed\n"); return 1;
    }
    printf("[+] task OK\n");

    g_regions = get_regions();
    printf("[+] %zu regions\n", g_regions.size());

    // Phase 1: Find "BasePlayer" strings
    printf("[*] Phase 1: Scanning for \"BasePlayer\" string...\n");
    auto str_hits = find_string("BasePlayer");
    printf("[+] Found %zu occurrences\n", str_hits.size());
    for (auto h : str_hits) {
        printf("    str @ 0x%llx: \"%s\"\n", h, read_cstr(h, 64).c_str());
    }

    if (str_hits.empty()) {
        printf("[!] No \"BasePlayer\" string found\n");
        return 1;
    }

    // Phase 2: Find pointers to those strings
    printf("\n[*] Phase 2: Finding pointers to strings...\n");
    std::vector<uint64_t> ptr_hits;
    for (auto s : str_hits) {
        auto ptrs = find_ptrs_to(s);
        printf("  str 0x%llx → %zu pointers\n", s, ptrs.size());
        for (auto p : ptrs) ptr_hits.push_back(p);
    }
    printf("[+] Total: %zu pointer hits\n", ptr_hits.size());

    // Phase 3: Validate as Il2CppClass
    // name field is at +0x10, so klass = ptr - 0x10
    printf("\n[*] Phase 3: Validating Il2CppClass candidates...\n");
    std::vector<KlassInfo> klasses;
    std::unordered_set<uint64_t> seen;

    for (auto ph : ptr_hits) {
        uint64_t klass = ph - 0x10;
        if (seen.count(klass)) continue;
        seen.insert(klass);

        // Read klass header
        uint8_t kbuf[0x100];
        if (!read_mem(klass, kbuf, sizeof(kbuf))) continue;

        // Check namespace at +0x18 (should be null or a valid string)
        uint64_t ns_ptr = *(uint64_t*)(kbuf + 0x18);
        std::string ns_name;
        if (ns_ptr && in_region(ns_ptr)) {
            ns_name = read_cstr(ns_ptr, 128);
        }

        // Validate: name at +0x10 should point to "BasePlayer"
        uint64_t name_ptr = *(uint64_t*)(kbuf + 0x10);
        std::string name_val = read_cstr(name_ptr, 64);

        printf("\n  [CANDIDATE] klass @ 0x%llx\n", klass);
        printf("    name=\"%s\" ns=\"%s\"\n", name_val.c_str(), ns_name.c_str());

        // The Il2CppClass pointer itself is what objects store at +0x00
        // So vtable_addr = klass
        KlassInfo ki;
        ki.klass_addr = klass;
        ki.vtable_addr = klass;
        ki.namespace_name = ns_name;
        klasses.push_back(ki);
    }

    printf("\n[+] %zu klass candidates\n", klasses.size());

    // Phase 4: Scan heap for objects whose first 8 bytes == klass
    if (!klasses.empty()) {
        uint64_t target_klass = klasses[0].klass_addr;
        printf("\n[*] Phase 4: Scanning heap for objects with klass=0x%llx\n", target_klass);

        const size_t CHUNK = 8 * 1024 * 1024;
        static uint8_t buf[8 * 1024 * 1024];
        int count = 0;
        std::vector<uint64_t> objects;

        for (auto& rg : g_regions) {
            if (!(rg.prot & 2)) continue; // writable (heap)
            if (rg.size() > 256 * 1024 * 1024) continue;
            for (uint64_t off = 0; off < rg.size(); off += CHUNK) {
                uint64_t chunk = std::min((uint64_t)CHUNK, rg.size() - off);
                mach_vm_size_t got = 0;
                if (mach_vm_read_overwrite(g_task, rg.start + off, chunk,
                                           (vm_address_t)buf, &got) != KERN_SUCCESS) break;
                size_t n = got / 8;
                for (size_t i = 0; i < n; i++) {
                    uint64_t v; memcpy(&v, buf + i * 8, 8);
                    if (v == target_klass) {
                        uint64_t obj = rg.start + off + i * 8;
                        objects.push_back(obj);
                        count++;
                    }
                }
            }
        }
        printf("[+] Found %zu objects with BasePlayer klass\n", objects.size());

        // For each object, try to read SteamID at various offsets
        const uint64_t SID_MIN = 76561198000000000ULL;
        const uint64_t SID_MAX = 76561200000000000ULL;

        printf("\n=== VALIDATED BASEPLAYERS ===\n");
        int valid = 0;
        for (auto obj : objects) {
            // Try SteamID at offsets around 0x6B0-0x6C0
            for (uint32_t sid_off = 0x6B0; sid_off <= 0x6C0; sid_off += 8) {
                uint64_t sid = r64(obj + sid_off);
                if (sid >= SID_MIN && sid < SID_MAX) {
                    // Read name
                    std::string name;
                    for (uint32_t nm_off = 0x480; nm_off <= 0x4A0; nm_off += 8) {
                        name = read_il2cpp_str(obj + nm_off);
                        if (name.size() >= 2) break;
                        name.clear();
                    }
                    // Read health
                    float hp = -1;
                    for (uint32_t hp_off = 0x298; hp_off <= 0x2A8; hp_off += 4) {
                        float h = rf(obj + hp_off);
                        if (std::isfinite(h) && h >= 0 && h <= 200) { hp = h; break; }
                    }
                    // Read flags
                    uint32_t flags = 0;
                    for (uint32_t fl_off = 0x668; fl_off <= 0x678; fl_off += 4) {
                        uint32_t f = r32(obj + fl_off);
                        // PlayerFlags: Sleeping=0x10, Connected=0x100, Wounded=0x40
                        // Valid flags should be relatively small
                        if (f < 0x10000) { flags = f; break; }
                    }

                    printf("  [BP] 0x%llx SID=%llu name=\"%s\" hp=%.0f flags=0x%x (sid@0x%x)\n",
                           obj, sid, name.c_str(), hp, flags, sid_off);
                    valid++;
                    break;
                }
            }
        }
        printf("\n  %d valid BasePlayers out of %zu objects\n", valid, objects.size());
    }

    return 0;
}