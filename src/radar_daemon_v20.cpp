// ============================================================================
// RR02 radar_daemon v20 — Parse Mach-O + scan __data pour listes d'entités
// ============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach-o/loader.h>
#include <mach-o/getsect.h>

typedef struct {
    uint32_t version;
    uint32_t infoArrayCount;
    const void* infoArray;
} dyld_all_image_infos_minimal;

typedef struct {
    const void* imageLoadAddress;
    const char* imageFilePath;
    uintptr_t imageFileModDate;
} dyld_image_info;

#define LOG(fmt, ...) printf("[*] " fmt "\n", ##__VA_ARGS__); fflush(stdout)
#define ERR(fmt, ...) printf("[!] " fmt "\n", ##__VA_ARGS__); fflush(stdout)

static task_t g_target_task = TASK_NULL;
static uint64_t g_base = 0;

static bool read_mem(mach_vm_address_t addr, void* buf, mach_vm_size_t len) {
    mach_vm_size_t outsize = 0;
    return (mach_vm_read_overwrite(g_target_task, addr, len, (mach_vm_address_t)buf, &outsize) == KERN_SUCCESS && outsize == len);
}

static uint64_t read_u64(mach_vm_address_t addr) {
    uint64_t v = 0; read_mem(addr, &v, 8); return v;
}

static uint32_t read_u32(mach_vm_address_t addr) {
    uint32_t v = 0; read_mem(addr, &v, 4); return v;
}

static bool find_base() {
    struct task_dyld_info dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    if (task_info(g_target_task, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count) != KERN_SUCCESS)
        return false;
    
    dyld_all_image_infos_minimal infos = {0};
    if (!read_mem(dyld_info.all_image_info_addr, &infos, sizeof(infos))) return false;
    
    dyld_image_info* array = (dyld_image_info*)malloc(sizeof(dyld_image_info) * infos.infoArrayCount);
    if (!array) return false;
    if (!read_mem((mach_vm_address_t)infos.infoArray, array, sizeof(dyld_image_info) * infos.infoArrayCount)) {
        free(array); return false;
    }
    
    bool found = false;
    for (uint32_t i = 0; i < infos.infoArrayCount; i++) {
        char path[512] = {0};
        read_mem((mach_vm_address_t)array[i].imageFilePath, path, sizeof(path));
        if (strstr(path, "GameAssembly")) {
            g_base = (uint64_t)array[i].imageLoadAddress;
            LOG("GameAssembly @ 0x%llx", g_base);
            found = true;
            break;
        }
    }
    free(array);
    return found;
}

// Parse Mach-O pour trouver une section
static bool get_section(uint64_t base, const char* seg, const char* sect, uint64_t* out_addr, uint64_t* out_size) {
    mach_header_64 hdr = {0};
    if (!read_mem(base, &hdr, sizeof(hdr))) return false;
    
    uint64_t addr = base + sizeof(hdr);
    for (uint32_t i = 0; i < hdr.ncmds; i++) {
        load_command lc = {0};
        if (!read_mem(addr, &lc, sizeof(lc))) return false;
        
        if (lc.cmd == LC_SEGMENT_64) {
            segment_command_64 seg_cmd = {0};
            if (!read_mem(addr, &seg_cmd, sizeof(seg_cmd))) return false;
            
            // Parcourir les sections
            uint64_t sec_addr = addr + sizeof(seg_cmd);
            for (uint32_t j = 0; j < seg_cmd.nsects; j++) {
                section_64 sec = {0};
                if (!read_mem(sec_addr, &sec, sizeof(sec))) return false;
                
                char segname[17] = {0}, sectname[17] = {0};
                memcpy(segname, seg_cmd.segname, 16);
                memcpy(sectname, sec.sectname, 16);
                
                if (strcmp(segname, seg) == 0 && strcmp(sectname, sect) == 0) {
                    *out_addr = sec.addr;
                    *out_size = sec.size;
                    LOG("Section %s,%s: addr=0x%llx size=0x%llx", seg, sect, *out_addr, *out_size);
                    return true;
                }
                sec_addr += sizeof(sec);
            }
        }
        addr += lc.cmdsize;
    }
    return false;
}

// Scanner la section __data pour trouver des listes d'entités
static int scan_data_section(uint64_t data_addr, uint64_t data_size) {
    // Lire toute la section
    uint8_t* buf = (uint8_t*)malloc(data_size);
    if (!buf) return 0;
    if (!read_mem(data_addr, buf, data_size)) { free(buf); return 0; }
    
    int found = 0;
    
    // Chercher des structures de liste:
    // Typiquement: [pointeur_vers_array] [int size] [int version]
    // On cherche des pointeurs (8 bytes) qui pointent vers des arrays de pointeurs
    
    for (uint64_t i = 0; i < data_size - 24; i += 8) {
        uint64_t ptr = *(uint64_t*)(buf + i);
        uint32_t size = *(uint32_t*)(buf + i + 8);
        uint32_t version = *(uint32_t*)(buf + i + 12);
        
        // Filtre: size plausible (1-1000), ptr aligné, version petite
        if (size > 0 && size < 1000 && version < 1000 && ptr > 0x100000000 && ptr < 0x2000000000) {
            // Vérifier si ptr pointe vers un array de pointeurs
            // Lire le premier élément
            uint64_t first = read_u64(ptr);
            if (first > 0x100000000 && first < 0x2000000000) {
                // Vérifier si c'est un BasePlayer (lire position approximative)
                // BasePlayer → BaseEntity → model (0x1B8) → rootBone (0x50) → position (0x40)
                // Ou bounds (0x18C) → center (0x0)
                
                // Test: lire bounds.center
                uint64_t bounds_ptr = read_u64(first + 0x18C);
                if (bounds_ptr > 0x100000000 && bounds_ptr < 0x2000000000) {
                    float x = 0, y = 0, z = 0;
                    read_mem(bounds_ptr, &x, 4);
                    read_mem(bounds_ptr + 4, &y, 4);
                    read_mem(bounds_ptr + 8, &z, 4);
                    
                    if (x > -5000 && x < 5000 && y > -100 && y < 1000 && z > -5000 && z < 5000) {
                        found++;
                        if (found <= 10) {
                            LOG("Joueur #%d: (%.1f, %.1f, %.1f) [size=%d]", found, x, y, z, size);
                        }
                    }
                }
            }
        }
    }
    
    free(buf);
    return found;
}

int main() {
    printf("=== RR02 radar v20 ===\n"); fflush(stdout);
    
    pid_t pids[2048];
    int n = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    for (int i = 0; i < n; i++) {
        char path[PROC_PIDPATHINFO_MAXSIZE];
        if (proc_pidpath(pids[i], path, sizeof(path)) > 0 && strstr(path, "RustClient")) {
            if (task_for_pid(mach_task_self(), pids[i], &g_target_task) == KERN_SUCCESS)
                break;
        }
    }
    if (!g_target_task) { ERR("task_for_pid failed"); return 1; }
    
    if (!find_base()) { ERR("GameAssembly non trouvé"); return 1; }
    
    // Trouver la section __data
    uint64_t data_addr = 0, data_size = 0;
    if (!get_section(g_base, "__DATA", "__data", &data_addr, &data_size)) {
        ERR("Section __data non trouvée");
        return 1;
    }
    
    LOG("Scan de __data (0x%llx bytes)...", data_size);
    
    int total = 0;
    for (int i = 0; i < 3; i++) {
        int n = scan_data_section(data_addr, data_size);
        total += n;
        LOG("Scan %d: %d joueurs", i+1, n);
        sleep(1);
    }
    
    LOG("Total: %d joueurs trouvés", total);
    
    int fd = open("/tmp/rr02_radar.json", O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (fd >= 0) { write(fd, "{\"players\":[]}", 14); close(fd); }
    
    return 0;
}
