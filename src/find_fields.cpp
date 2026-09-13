// ============================================================================
// RR02/find_fields.cpp — Find FieldInfo array by trying all pointers in klass
// and checking if they point to readable field names (without region check)
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

static std::string read_cstr(uint64_t a, size_t max=64) {
    if (!vptr(a)) return "";
    std::string s; char buf[64];
    size_t read = 0;
    while (read < max) {
        if (!read_mem(a + read, buf, std::min(max - read, (size_t)64))) break;
        for (size_t i = 0; i < std::min(max - read, (size_t)64); i++) {
            if (buf[i] == 0) return s;
            if (buf[i] >= 32 && buf[i] < 127) s += buf[i];
            else return s;
            read++;
        }
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

// FieldInfo layouts to try
// layout: {name_offset, offset_offset, stride}
struct FL { int noff, ooff, stride; };
static FL field_layouts[] = {
    {0x00, 0x10, 32}, {0x00, 0x18, 32}, {0x00, 0x10, 24},
    {0x08, 0x10, 32}, {0x08, 0x18, 32}, {0x08, 0x10, 24},
    {0x08, 0x1C, 32}, {0x00, 0x14, 24}, {0x00, 0x0C, 16},
    {0x08, 0x14, 24}, {0x08, 0x0C, 16},
};

static const uint64_t BASEPLAYER_KLASS = 0x105be6640;

void try_fields(uint64_t fp, FL& fl, const char* klass_name) {
    // Read 5 FieldInfo entries
    for (int i = 0; i < 5; i++) {
        uint8_t fb[32];
        if (!read_mem(fp + i * fl.stride, fb, fl.stride)) continue;
        uint64_t name_addr = *(uint64_t*)(fb + fl.noff);
        if (!vptr(name_addr)) continue;
        std::string s = read_cstr(name_addr, 40);
        if (s.size() < 1 || s.size() > 50) continue;
        if (!isalpha(s[0]) && s[0] != '<' && s[0] != '_') continue;
        // At least 3 out of 5 should be valid
        int valid = 0;
        for (int j = 0; j < 5; j++) {
            uint8_t fb2[32];
            if (!read_mem(fp + j * fl.stride, fb2, fl.stride)) continue;
            uint64_t na = *(uint64_t*)(fb2 + fl.noff);
            if (!vptr(na)) continue;
            std::string ns = read_cstr(na, 40);
            if (ns.size() >= 1 && ns.size() <= 50 && (isalpha(ns[0]) || ns[0]=='<' || ns[0]=='_'))
                valid++;
        }
        if (valid < 3) continue;

        printf("\n  [%s] fields @ 0x%llx (name@+%d, off@+%d, stride=%d)\n",
               klass_name, fp, fl.noff, fl.ooff, fl.stride);
        int count = 0;
        for (int fi = 0; fi < 500; fi++) {
            uint8_t f[32];
            if (!read_mem(fp + fi * fl.stride, f, fl.stride)) break;
            uint64_t name_addr = *(uint64_t*)(f + fl.noff);
            if (!vptr(name_addr)) break;
            std::string name = read_cstr(name_addr, 64);
            if (name.empty() || name.size() > 64) break;
            uint32_t foff = 0;
            memcpy(&foff, f + fl.ooff, 4);
            if (foff > 0x4000 && fi > 0) break;
            printf("    +0x%04x  %s\n", foff, name.c_str());
            count++;
        }
        printf("    → %d fields\n", count);
    }
}

int main() {
    printf("=== RR02 Find Fields ===\n");
    pid_t pid = find_rust();
    if (pid < 0) { printf("[!] Rust not found\n"); return 1; }
    if (task_for_pid(mach_task_self(), pid, &g_task) != KERN_SUCCESS) {
        printf("[!] task_for_pid failed\n"); return 1;
    }
    printf("[+] Rust pid=%d\n", pid);

    // Walk class hierarchy
    uint64_t klasses[] = {0x105be6640 /* BasePlayer */, 0x105838a90 /* BaseCombatEntity */,
                         0x1058323f0 /* BaseEntity */, 0x105832fa0 /* BaseNetworkable */};
    const char* knames[] = {"BasePlayer", "BaseCombatEntity", "BaseEntity", "BaseNetworkable"};

    for (int ki = 0; ki < 4; ki++) {
        uint64_t klass = klasses[ki];
        printf("\n========================================\n");
        printf("Scanning %s @ 0x%llx\n", knames[ki], klass);
        printf("========================================\n");

        uint8_t kbuf[0x300];
        if (!read_mem(klass, kbuf, 0x300)) {
            printf("[!] Can't read klass\n"); continue;
        }

        // Try each 8-byte aligned pointer in the klass
        for (int wi = 0; wi < 0x300/8; wi++) {
            uint64_t fp = *(uint64_t*)(kbuf + wi*8);
            if (!vptr(fp)) continue;
            for (auto& fl : field_layouts) {
                try_fields(fp, fl, knames[ki]);
            }
        }
    }

    return 0;
}