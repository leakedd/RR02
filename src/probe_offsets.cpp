// ============================================================================
// RR02/probe_offsets.cpp — Probe real BasePlayer objects for live offsets
// Uses klass=0x105be6640 found by find_class
// Scans offset 0x000-0x800 for: SteamID, displayName, health, position
// Compile: c++ -O2 -std=c++17 -o probe_offsets probe_offsets.cpp
// Run: echo PASSWORD | sudo -S ./probe_offsets
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

static std::string read_cstr(uint64_t a, size_t max=128) {
    std::string s; char buf[128];
    for (size_t off=0; off<max; off+=128) {
        size_t ch=std::min((size_t)128, max-off);
        if(!read_mem(a+off,buf,ch)) break;
        for(size_t i=0;i<ch;i++){ if(buf[i]==0) return s; if(buf[i]>=32&&buf[i]<127) s+=buf[i]; else return s; }
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
    pid_t pids[4096]; int n = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    for (int i=0; i<n/(int)sizeof(pid_t); i++) {
        char path[1024]; if (proc_pidpath(pids[i],path,sizeof(path))>0 && strstr(path,"RustClient")) return pids[i];
    }
    return -1;
}

struct Region { uint64_t start,end; uint32_t prot; uint64_t sz() const { return end-start; } };

static std::vector<Region> get_regions() {
    std::vector<Region> r;
    mach_vm_address_t a=0; mach_vm_size_t sz; vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt; mach_port_t obj;
    while(true) {
        cnt=VM_REGION_BASIC_INFO_COUNT_64;
        if(mach_vm_region(g_task,&a,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&cnt,&obj)!=KERN_SUCCESS) break;
        if(info.protection&VM_PROT_READ) r.push_back({a,a+sz,(uint32_t)info.protection});
        a+=sz;
    }
    return r;
}

static const uint64_t SID_MIN = 76561198000000000ULL;
static const uint64_t SID_MAX = 76561200000000000ULL;

// Known klass from find_class
static const uint64_t BASEPLAYER_KLASS = 0x105be6640;

int main() {
    printf("=== RR02 Probe Offsets ===\n");
    pid_t pid = find_rust();
    if (pid < 0) { printf("[!] Rust not found\n"); return 1; }
    printf("[+] Rust pid=%d\n", pid);
    if (task_for_pid(mach_task_self(), pid, &g_task) != KERN_SUCCESS) {
        printf("[!] task_for_pid failed\n"); return 1;
    }
    printf("[+] task OK\n");
    auto regions = get_regions();
    printf("[+] %zu regions\n", regions.size());

    // Verify klass
    uint64_t name_ptr = r64(BASEPLAYER_KLASS + 0x10);
    std::string klass_name = read_cstr(name_ptr, 64);
    printf("[+] klass @ 0x%llx name=\"%s\"\n", BASEPLAYER_KLASS, klass_name.c_str());
    if (klass_name != "BasePlayer") {
        printf("[!] klass name mismatch, aborting\n");
        return 1;
    }

    // Scan heap for objects with this klass
    printf("[*] Scanning heap for BasePlayer objects...\n");
    const size_t CHUNK = 8*1024*1024;
    static uint8_t buf[8*1024*1024];
    std::vector<uint64_t> objects;
    int ri=0;
    for (auto& rg : regions) {
        ri++;
        if (!(rg.prot & 2)) continue; // writable
        if (rg.sz() > 256*1024*1024) continue;
        for (uint64_t off=0; off<rg.sz(); off+=CHUNK) {
            uint64_t ch=std::min((uint64_t)CHUNK, rg.sz()-off);
            mach_vm_size_t got=0;
            if (mach_vm_read_overwrite(g_task, rg.start+off, ch, (vm_address_t)buf, &got)!=KERN_SUCCESS) break;
            size_t n=got/8;
            for (size_t i=0; i<n; i++) {
                uint64_t v; memcpy(&v, buf+i*8, 8);
                if (v == BASEPLAYER_KLASS) objects.push_back(rg.start+off+i*8);
            }
        }
    }
    printf("[+] Found %zu objects\n", objects.size());

    // For the first 50 objects, scan offsets 0x000-0x800 for:
    // - SteamID (uint64 in range)
    // - Il2CppString name (pointer → valid string)
    // - Health (float 0-200)
    // - Position (3x float, world coords)

    printf("\n=== Probing first 50 objects ===\n");

    struct OffsetHit {
        uint32_t offset;
        int count;
    };

    std::unordered_map<uint32_t, int> sid_hits;
    std::unordered_map<uint32_t, int> name_hits;
    std::unordered_map<uint32_t, int> hp_hits;

    int probe_count = std::min((size_t)50, objects.size());
    for (int oi=0; oi<probe_count; oi++) {
        uint64_t obj = objects[oi];
        // Read 0x800 bytes from object
        static uint8_t obuf[0x800];
        if (!read_mem(obj, obuf, 0x800)) continue;

        for (uint32_t off=0; off<0x800; off+=8) {
            // SteamID check (uint64)
            if (off + 8 <= 0x800) {
                uint64_t v; memcpy(&v, obuf+off, 8);
                if (v >= SID_MIN && v < SID_MAX) {
                    sid_hits[off]++;
                }
            }
        }
        for (uint32_t off=0; off<0x800; off+=8) {
            // Name check (pointer → Il2CppString → text)
            if (off + 8 <= 0x800) {
                uint64_t p; memcpy(&p, obuf+off, 8);
                if (!vptr(p)) continue;
                std::string s = read_il2cpp_str(obj+off);
                if (s.size() >= 2 && s.size() <= 40 &&
                    s.find(".prefab")==std::string::npos &&
                    s.find("UnityEngine")==std::string::npos) {
                    name_hits[off]++;
                }
            }
        }
        for (uint32_t off=0; off<0x800; off+=4) {
            // Health check (float 0-200)
            if (off + 4 <= 0x800) {
                float f; memcpy(&f, obuf+off, 4);
                if (std::isfinite(f) && f > 0 && f <= 200) {
                    hp_hits[off]++;
                }
            }
        }
    }

    // Report SteamID offsets (sorted by hit count)
    printf("\n=== SteamID Offset Candidates ===\n");
    std::vector<std::pair<int,uint32_t>> sid_sorted;
    for (auto& [off, cnt] : sid_hits) sid_sorted.push_back({cnt, off});
    std::sort(sid_sorted.rbegin(), sid_sorted.rend());
    for (auto& [cnt, off] : sid_sorted) {
        if (cnt < 2) break;
        printf("  +0x%04x: %d/%d hits\n", off, cnt, probe_count);
    }

    // Report Name offsets
    printf("\n=== Name Offset Candidates ===\n");
    std::vector<std::pair<int,uint32_t>> name_sorted;
    for (auto& [off, cnt] : name_hits) name_sorted.push_back({cnt, off});
    std::sort(name_sorted.rbegin(), name_sorted.rend());
    for (auto& [cnt, off] : name_sorted) {
        if (cnt < 2) break;
        printf("  +0x%04x: %d/%d hits\n", off, cnt, probe_count);
    }

    // Report Health offsets
    printf("\n=== Health Offset Candidates ===\n");
    std::vector<std::pair<int,uint32_t>> hp_sorted;
    for (auto& [off, cnt] : hp_hits) hp_sorted.push_back({cnt, off});
    std::sort(hp_sorted.rbegin(), hp_sorted.rend());
    for (auto& [cnt, off] : hp_sorted) {
        if (cnt < 3) break; // health is common float, require more hits
        printf("  +0x%04x: %d/%d hits\n", off, cnt, probe_count);
    }

    // For the best SteamID offset, dump full player info
    if (!sid_sorted.empty() && sid_sorted[0].first >= 2) {
        uint32_t best_sid_off = sid_sorted[0].second;
        printf("\n=== Best SteamID offset: +0x%04x ===\n", best_sid_off);
        printf("\n=== Validated Players ===\n");
        int valid = 0;
        for (auto obj : objects) {
            uint64_t sid = r64(obj + best_sid_off);
            if (sid < SID_MIN || sid >= SID_MAX) continue;

            // Try to find name
            std::string name;
            for (auto& [nm_off, nm_cnt] : name_sorted) {
                if (nm_cnt >= 2) {
                    name = read_il2cpp_str(obj + nm_off);
                    if (name.size() >= 2) break;
                }
                name.clear();
            }

            // Try to find health
            float hp = -1;
            for (auto& [hp_off, hp_cnt] : hp_sorted) {
                if (hp_cnt >= 3) {
                    float h = rf(obj + hp_off);
                    if (std::isfinite(h) && h >= 0 && h <= 200) { hp = h; break; }
                }
            }

            printf("  [BP] 0x%llx SID=%llu name=\"%s\" hp=%.0f\n",
                   obj, sid, name.c_str(), hp);
            valid++;
            if (valid >= 30) break;
        }
        printf("\n  %d valid players\n", valid);
    } else {
        printf("\n[!] No reliable SteamID offset found\n");
        printf("[*] Dumping first 5 objects (hex dump 0x000-0x100):\n");
        for (int i=0; i<std::min((size_t)5, objects.size()); i++) {
            printf("\n  Object %d @ 0x%llx:\n", i, objects[i]);
            uint8_t d[0x100];
            if (!read_mem(objects[i], d, 0x100)) continue;
            for (int row=0; row<0x100; row+=16) {
                printf("    %04x: ", row);
                for (int j=0; j<16; j++) printf("%02x ", d[row+j]);
                printf(" |");
                for (int j=0; j<16; j++) { char c=d[row+j]; printf("%c", (c>=32&&c<127)?c:'.'); }
                printf("|\n");
            }
        }
    }

    return 0;
}