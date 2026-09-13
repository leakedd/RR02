// ============================================================================
// RR02 radar_daemon v19 — Ciblé via dyld_all_image_infos
// ============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/time.h>
#include <libproc.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>

typedef struct {
    uint32_t version;
    uint32_t infoArrayCount;
    const void* infoArray;
} dyld_all_image_infos;

typedef struct {
    const void* imageLoadAddress;
    const char* imageFilePath;
    uintptr_t imageFileModDate;
} dyld_image_info;

#define LOG(fmt, ...) printf("[*] " fmt "\n", ##__VA_ARGS__); fflush(stdout)
#define ERR(fmt, ...) printf("[!] " fmt "\n", ##__VA_ARGS__); fflush(stdout)

static pid_t g_target_pid = 0;
static task_t g_target_task = TASK_NULL;
static uint64_t g_aslr_base = 0;

static bool read_mem(mach_vm_address_t addr, void* buf, mach_vm_size_t len) {
    mach_vm_size_t outsize = 0;
    kern_return_t kr = mach_vm_read_overwrite(g_target_task, addr, len, (mach_vm_address_t)buf, &outsize);
    return (kr == KERN_SUCCESS && outsize == len);
}

static uint64_t read_u64(mach_vm_address_t addr) {
    uint64_t v = 0; read_mem(addr, &v, 8); return v;
}

static bool find_gameassembly() {
    struct task_dyld_info dyld_info;
    mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
    if (task_info(g_target_task, TASK_DYLD_INFO, (task_info_t)&dyld_info, &count) != KERN_SUCCESS)
        return false;
    
    LOG("dyld_all_image_infos @ 0x%llx", dyld_info.all_image_info_addr);
    
    dyld_all_image_infos infos = {0};
    if (!read_mem(dyld_info.all_image_info_addr, &infos, sizeof(infos))) return false;
    
    LOG("dyld version: %d, images: %u", infos.version, infos.infoArrayCount);
    
    dyld_image_info* array = (dyld_image_info*)malloc(sizeof(dyld_image_info) * infos.infoArrayCount);
    if (!array) return false;
    if (!read_mem((mach_vm_address_t)infos.infoArray, array, sizeof(dyld_image_info) * infos.infoArrayCount)) {
        free(array);
        return false;
    }
    
    bool found = false;
    for (uint32_t i = 0; i < infos.infoArrayCount; i++) {
        char path[512] = {0};
        read_mem((mach_vm_address_t)array[i].imageFilePath, path, sizeof(path));
        
        if (strstr(path, "GameAssembly")) {
            g_aslr_base = (uint64_t)array[i].imageLoadAddress;
            LOG("Trouvé: %s @ 0x%llx", path, g_aslr_base);
            found = true;
            break;
        }
    }
    
    free(array);
    return found;
}

static int scan() {
    if (!find_gameassembly()) { ERR("GameAssembly non trouvé"); return 0; }
    
    // Lire header pour vérifier
    uint64_t magic = read_u64(g_aslr_base);
    LOG("Magic @ base: 0x%llx", magic);
    
    // Chercher Vec3 dans les données
    uint8_t buf[0x100000];
    if (!read_mem(g_aslr_base, buf, sizeof(buf))) return 0;
    
    int found = 0;
    for (size_t i = 0; i < sizeof(buf) - 12; i += 4) {
        float* f = (float*)(buf + i);
        if (f[0] > -5000 && f[0] < 5000 && f[1] > -100 && f[1] < 1000 && f[2] > -5000 && f[2] < 5000 && (f[0] != 0 || f[1] != 0 || f[2] != 0)) {
            found++;
            if (found <= 5) LOG("Vec3 @ 0x%zx: (%.1f, %.1f, %.1f)", i, f[0], f[1], f[2]);
        }
    }
    LOG("Total Vec3: %d", found);
    return found;
}

int main() {
    printf("=== RR02 radar v19 ===\n"); fflush(stdout);
    
    pid_t pids[2048];
    int n = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    for (int i = 0; i < n; i++) {
        char path[PROC_PIDPATHINFO_MAXSIZE];
        if (proc_pidpath(pids[i], path, sizeof(path)) > 0 && strstr(path, "RustClient")) {
            g_target_pid = pids[i]; break;
        }
    }
    if (!g_target_pid) { ERR("RustClient non trouvé"); return 1; }
    LOG("RustClient PID: %d", g_target_pid);
    
    if (task_for_pid(mach_task_self(), g_target_pid, &g_target_task) != KERN_SUCCESS) {
        ERR("task_for_pid failed"); return 1;
    }
    LOG("task_for_pid OK");
    
    int total = 0;
    struct timeval start, now;
    gettimeofday(&start, NULL);
    
    while (1) {
        total += scan();
        gettimeofday(&now, NULL);
        if (now.tv_sec - start.tv_sec >= 8) break;
        usleep(500000);
    }
    
    LOG("Terminé: %d Vec3", total);
    
    int fd = open("/tmp/rr02_radar.json", O_WRONLY|O_CREAT|O_TRUNC, 0644);
    if (fd >= 0) { write(fd, "{\"players\":[]}", 14); close(fd); }
    
    return 0;
}
