// ============================================================================
// RR02/dump_klass.cpp — Dump Il2CppClass fields from live memory
// We know klass is at 0x105be6640 in Rust's memory
// IL2CPP v39 Il2CppClass struct on ARM64:
//   0x00: image
//   0x08: gc_desc
//   0x10: name (char*)
//   0x18: namespaze (char*)
//   0x20: byval_arg (Il2CppType)
//   0x30: this_arg
//   0x40: element_class
//   0x48: castClass
//   0x50: native_size
//   0x58: static_fields
//   0x60: rgctx_data
//   ...
//   0x80: fields (FieldInfo*)
//   ...
//   0xB8: field_count
//   ...
// 
// On IL2CPP v39 ARM64, the actual offsets are:
//   FieldInfo: { char* name, Il2CppType* type, uint32_t offset, ... }
//   Each FieldInfo is ~32 bytes
//
// We'll dump 0x200 bytes of the klass and try to find field info
// Compile: c++ -O2 -std=c++17 -o dump_klass dump_klass.cpp
// Run: echo PASSWORD | sudo -S ./dump_klass
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
static uint16_t r16(uint64_t a) { uint16_t v{}; read_mem(a, &v, 2); return v; }
static bool vptr(uint64_t p) { return p > 0x100000ULL && p < 0x800000000000ULL; }

static std::string read_cstr(uint64_t a, size_t max=256) {
    std::string s; char buf[256];
    for (size_t off=0; off<max; off+=256) {
        size_t ch=std::min((size_t)256, max-off);
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
    for (auto& r : g_regions)
        if (a >= r.start && a < r.end) return true;
    return false;
}

static const uint64_t BASEPLAYER_KLASS = 0x105be6640;

int main() {
    printf("=== RR02 Dump Klass ===\n");
    pid_t pid = find_rust();
    if (pid < 0) { printf("[!] Rust not found\n"); return 1; }
    if (task_for_pid(mach_task_self(), pid, &g_task) != KERN_SUCCESS) {
        printf("[!] task_for_pid failed\n"); return 1;
    }
    printf("[+] Rust pid=%d\n", pid);

    // Get regions for validation
    mach_vm_address_t addr=0; mach_vm_size_t sz; vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt; mach_port_t obj;
    while(true) {
        cnt=VM_REGION_BASIC_INFO_COUNT_64;
        if(mach_vm_region(g_task,&addr,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&cnt,&obj)!=KERN_SUCCESS) break;
        if(info.protection&VM_PROT_READ) g_regions.push_back({addr,addr+sz,(uint32_t)info.protection});
        addr+=sz;
    }
    printf("[+] %zu regions\n", g_regions.size());

    // Dump klass header (0x200 bytes)
    uint8_t kbuf[0x200];
    if (!read_mem(BASEPLAYER_KLASS, kbuf, 0x200)) {
        printf("[!] Can't read klass memory\n"); return 1;
    }

    printf("\n=== Il2CppClass @ 0x%llx ===\n", BASEPLAYER_KLASS);
    printf("Hex dump:\n");
    for (int row=0; row<0x200; row+=16) {
        printf("  %04x: ", row);
        for (int j=0; j<16; j++) printf("%02x ", kbuf[row+j]);
        printf(" |");
        for (int j=0; j<16; j++) { char c=(char)kbuf[row+j]; printf("%c", (c>=32&&c<127)?c:'.'); }
        printf("|\n");
    }

    // Parse known fields
    uint64_t name_ptr = *(uint64_t*)(kbuf + 0x10);
    uint64_t ns_ptr = *(uint64_t*)(kbuf + 0x18);
    printf("\nname (0x10) = 0x%llx → \"%s\"\n", name_ptr, read_cstr(name_ptr, 64).c_str());
    printf("namespaze (0x18) = 0x%llx → \"%s\"\n", ns_ptr, ns_ptr ? read_cstr(ns_ptr, 64).c_str() : "(null)");

    // Try to find field info at various offsets
    // IL2CPP v39 Il2CppClass fields:
    //   fields (FieldInfo*) at different possible offsets
    //   field_count at different possible offsets
    //
    // FieldInfo on v39: { char* name, Il2CppType* type, uint32_t offset, FieldInfo* parent? }
    //   Actually on v39: FieldInfo = { parent (Il2CppClass*), name (char*), type (Il2CppType*), offset (uint32_t) }
    //   Size = 32 bytes on 64-bit

    printf("\n=== Scanning for FieldInfo array ===\n");
    // Try each pointer in klass+0x10..0x1F8 as potential fields pointer
    // A valid FieldInfo[0] should have:
    //   +0x00: parent (klass or similar, should be a valid pointer)
    //   +0x08: name (char*, valid string)
    //   +0x10: type (Il2CppType*, valid pointer)
    //   +0x18: offset (uint32, reasonable small number)

    for (int wi=2; wi<0x40; wi++) {
        uint64_t fp = *(uint64_t*)(kbuf + wi*8);
        if (!vptr(fp) || !in_region(fp)) continue;
        
        // Read first FieldInfo (32 bytes)
        uint8_t fib[32];
        if (!read_mem(fp, fib, 32)) continue;
        
        uint64_t f_parent = *(uint64_t*)(fib + 0);
        uint64_t f_name = *(uint64_t*)(fib + 8);
        uint64_t f_type = *(uint64_t*)(fib + 16);
        uint32_t f_offset = *(uint32_t*)(fib + 24);
        
        // Validate: name should be a valid string
        if (!vptr(f_name)) continue;
        std::string fname = read_cstr(f_name, 64);
        if (fname.size() < 2 || fname.size() > 64) continue;
        if (fname[0] == '_' && fname.find("__") == 0) { /* skip backing fields */ }
        
        // Validate: offset should be reasonable (0-0x2000)
        if (f_offset > 0x2000) continue;
        
        // Validate: type should be a valid pointer
        if (!vptr(f_type)) continue;
        
        printf("\n  [FIELDS] klass+0x%04x → fields @ 0x%llx\n", wi*8, fp);
        printf("    First field: name=\"%s\" offset=0x%x type=0x%llx parent=0x%llx\n",
               fname.c_str(), f_offset, f_type, f_parent);
        
        // Dump up to 200 fields
        int field_count = 0;
        for (int fi=0; fi<200; fi++) {
            uint8_t fb[32];
            if (!read_mem(fp + fi*32, fb, 32)) break;
            uint64_t fn = *(uint64_t*)(fb + 8);
            if (!vptr(fn)) break;
            std::string fnm = read_cstr(fn, 64);
            if (fnm.empty() || fnm.size() > 64) break;
            uint32_t foff = *(uint32_t*)(fb + 24);
            if (foff > 0x4000 && fi > 0) break; // first few might have 0
            uint64_t ftype = *(uint64_t*)(fb + 16);
            printf("    +0x%04x  %-40s (type=0x%llx)\n", foff, fnm.c_str(), ftype);
            field_count++;
        }
        printf("    → %d fields dumped\n", field_count);
        break; // take first valid one
    }

    // Also dump the parent class
    uint64_t parent = *(uint64_t*)(kbuf + 0x40); // element_class/castClass area
    printf("\n=== Parent class check ===\n");
    for (int off=0x40; off<0x80; off+=8) {
        uint64_t p = *(uint64_t*)(kbuf + off);
        if (vptr(p) && in_region(p)) {
            uint64_t pn = r64(p + 0x10);
            if (vptr(pn)) {
                std::string pname = read_cstr(pn, 64);
                if (pname.size() >= 2 && pname.size() <= 64) {
                    printf("  klass+0x%02x → 0x%llx name=\"%s\"\n", off, p, pname.c_str());
                }
            }
        }
    }

    return 0;
}