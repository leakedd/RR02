// ============================================================================
// RR02/deep_klass.cpp — Deep inspection of Il2CppClass v39 on ARM64 macOS
// 
// IL2CPP v39 Il2CppClass is ~0x300 bytes. We need to find:
// 1. The fields array pointer and field_count
// 2. The instance_size
// 3. Field offsets for: userID (SteamID), displayName, health, playerModel
//
// FieldInfo on IL2CPP v39 (ARM64):
//   { Il2CppType* type (8), const char* name (8), FieldInfo* parent (8), int32_t offset (4), uint32_t token (4) }
//   = 32 bytes per FieldInfo
//   OR:
//   { const char* name (8), Il2CppType* type (8), uint32_t offset (4), Pad (4), FieldInfo* parent (8) }
//   = 32 bytes
//
// We'll scan all pointers in klass 0x00-0x300 and try to interpret as FieldInfo arrays
// with different layouts until we find one that gives readable field names like
// "userID", "player", "health", etc.
// ============================================================================

#include <cstdio>
#include <cstdint>
#include <cstring>
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
static uint64_t r64(uint64_t a) { uint64_t v{}; read_mem(a, &v, 8); return v; }
static uint32_t r32(uint64_t a) { uint32_t v{}; read_mem(a, &v, 4); return v; }
static bool vptr(uint64_t p) { return p > 0x100000ULL && p < 0x800000000000ULL; }

static std::string read_cstr(uint64_t a, size_t max=128) {
    if (!vptr(a)) return "";
    std::string s; char buf[128];
    for (size_t off=0; off<max; off+=128) {
        size_t ch=std::min((size_t)128, max-off);
        if(!read_mem(a+off,buf,ch)) break;
        for(size_t i=0;i<ch;i++){ if(buf[i]==0) return s; if(buf[i]>=32&&buf[i]<127) s+=buf[i]; else return s; }
    }
    return s;
}

static pid_t find_rust() {
    pid_t pids[4096]; int n = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    for (int i=0; i<n/(int)sizeof(pid_t); i++) {
        char path[1024]; if (proc_pidpath(pids[i],path,sizeof(path))>0 && strstr(path,"RustClient")) return pids[i];
    }
    return -1;
}

struct Region { uint64_t start, end; uint32_t prot; };
static std::vector<Region> g_regions;
static bool in_region(uint64_t a) {
    for (auto& r : g_regions) if (a >= r.start && a < r.end) return true;
    return false;
}

// Try different FieldInfo layouts
struct FieldLayout {
    int name_off;    // offset of name pointer in FieldInfo
    int type_off;    // offset of type pointer
    int offset_off;  // offset of field offset value
    int size;        // size of each FieldInfo
};

static FieldLayout layouts[] = {
    {0, 8, 16, 24},   // name, type, offset — 24 bytes
    {8, 16, 24, 32},  // parent, name, type, offset — 32 bytes  
    {0, 8, 24, 32},   // name, type, ?, offset — 32 bytes
    {8, 0, 24, 32},   // type, name, ?, offset — 32 bytes
    {8, 16, 20, 32},  // parent, name, type(8), offset(4) — 32 bytes  
    {0, 8, 16, 32},   // name, type, offset at 16, 32 byte stride
    {16, 8, 28, 32},  // type, name, ..., offset at 28
    {0, 16, 8, 32},   // name, ?, type, ...
};

static const uint64_t BASEPLAYER_KLASS = 0x105be6640;

void try_fields(uint64_t fields_ptr, FieldLayout& fl) {
    // Read first 3 FieldInfo entries
    uint8_t fb[3][32];
    for (int i = 0; i < 3; i++) {
        if (!read_mem(fields_ptr + i * fl.size, fb[i], fl.size)) return;
    }

    // Check that names are valid strings
    for (int i = 0; i < 3; i++) {
        uint64_t name_addr = *(uint64_t*)(fb[i] + fl.name_off);
        if (!vptr(name_addr)) return;
        std::string s = read_cstr(name_addr, 40);
        if (s.size() < 1 || s.size() > 50) return;
        // First char should be a letter
        if (!isalpha(s[0]) && s[0] != '<' && s[0] != '_') return;
    }

    printf("  [FOUND] fields @ 0x%llx, layout: name@+%d type@+%d offset@+%d stride=%d\n",
           fields_ptr, fl.name_off, fl.type_off, fl.offset_off, fl.size);

    // Dump all fields
    int count = 0;
    for (int fi = 0; fi < 400; fi++) {
        uint8_t f[32];
        if (!read_mem(fields_ptr + fi * fl.size, f, fl.size)) break;
        uint64_t name_addr = *(uint64_t*)(f + fl.name_off);
        if (!vptr(name_addr)) break;
        std::string name = read_cstr(name_addr, 64);
        if (name.empty() || name.size() > 64) break;
        uint32_t foff = *(uint32_t*)(f + fl.offset_off);
        if (foff > 0x4000 && fi > 0) break;
        uint64_t ftype = *(uint64_t*)(f + fl.type_off);
        printf("    +0x%04x  %-45s (type=0x%llx)\n", foff, name.c_str(), ftype);
        count++;
    }
    printf("    → %d fields\n", count);
}

int main() {
    printf("=== RR02 Deep Klass ===\n");
    pid_t pid = find_rust();
    if (pid < 0) { printf("[!] Rust not found\n"); return 1; }
    if (task_for_pid(mach_task_self(), pid, &g_task) != KERN_SUCCESS) {
        printf("[!] task_for_pid failed\n"); return 1;
    }
    printf("[+] Rust pid=%d\n", pid);

    mach_vm_address_t addr=0; mach_vm_size_t sz; vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt; mach_port_t obj;
    while(true) {
        cnt=VM_REGION_BASIC_INFO_COUNT_64;
        if(mach_vm_region(g_task,&addr,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&cnt,&obj)!=KERN_SUCCESS) break;
        if(info.protection&VM_PROT_READ) g_regions.push_back({addr,addr+sz,(uint32_t)info.protection});
        addr+=sz;
    }

    // Dump 0x300 bytes of BasePlayer klass
    uint8_t kbuf[0x300];
    if (!read_mem(BASEPLAYER_KLASS, kbuf, 0x300)) {
        printf("[!] Can't read klass\n"); return 1;
    }

    printf("[+] BasePlayer klass @ 0x%llx\n", BASEPLAYER_KLASS);
    
    // Also dump BaseCombatEntity (parent)
    uint64_t parent = r64(BASEPLAYER_KLASS + 0x58);
    printf("[+] Parent (BaseCombatEntity) @ 0x%llx\n", parent);
    
    uint8_t pbuf[0x300];
    if (read_mem(parent, pbuf, 0x300)) {
        printf("[+] Parent name: \"%s\"\n", read_cstr(*(uint64_t*)(pbuf + 0x10), 64).c_str());
    }

    // Try each pointer in both klass as potential FieldInfo array
    printf("\n=== Scanning BasePlayer klass for FieldInfo ===\n");
    for (int wi = 0; wi < 0x300/8; wi++) {
        uint64_t fp = *(uint64_t*)(kbuf + wi*8);
        if (!vptr(fp) || !in_region(fp)) continue;
        for (auto& fl : layouts) {
            try_fields(fp, fl);
        }
    }

    printf("\n=== Scanning BaseCombatEntity klass for FieldInfo ===\n");
    for (int wi = 0; wi < 0x300/8; wi++) {
        uint64_t fp = *(uint64_t*)(pbuf + wi*8);
        if (!vptr(fp) || !in_region(fp)) continue;
        for (auto& fl : layouts) {
            try_fields(fp, fl);
        }
    }

    // Walk up the parent chain and dump each class
    printf("\n=== Class hierarchy ===\n");
    uint64_t cur = BASEPLAYER_KLASS;
    for (int depth = 0; depth < 10 && vptr(cur); depth++) {
        uint8_t cb[0x100];
        if (!read_mem(cur, cb, 0x100)) break;
        uint64_t name_p = *(uint64_t*)(cb + 0x10);
        std::string name = vptr(name_p) ? read_cstr(name_p, 64) : "?";
        printf("  %*s0x%llx \"%s\"\n", depth*2, "", cur, name.c_str());
        // parent at +0x58
        cur = *(uint64_t*)(cb + 0x58);
        if (cur == BASEPLAYER_KLASS || cur == 0) break;
    }

    return 0;
}