// brute_sf.cpp — brute-force static_fields offset in BaseNetworkable klass (0x103a80990)
// For each candidate sf ptr from klass, follow Cl1k path: sf+0x08 → decrypt → handle → entity list
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <unistd.h>

static mach_port_t task;
static int r64(uint64_t a, uint64_t* v) {
    mach_vm_size_t sz = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, (mach_vm_address_t)a, 8, (mach_vm_address_t)v, &sz);
    return kr == KERN_SUCCESS && sz == 8 ? 0 : -1;
}
static int r32(uint64_t a, uint32_t* v) {
    mach_vm_size_t sz = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, (mach_vm_address_t)a, 4, (mach_vm_address_t)v, &sz);
    return kr == KERN_SUCCESS && sz == 4 ? 0 : -1;
}
static int r8(uint64_t a, uint8_t* v) {
    mach_vm_size_t sz = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, (mach_vm_address_t)a, 1, (mach_vm_address_t)v, &sz);
    return kr == KERN_SUCCESS && sz == 1 ? 0 : -1;
}
static void cstr(uint64_t a, char* out, size_t n) {
    out[0] = 0;
    uint8_t b[64];
    mach_vm_size_t sz = 0;
    if (mach_vm_read_overwrite(task, a, 63, (mach_vm_address_t)b, &sz) != KERN_SUCCESS) return;
    size_t i = 0;
    while (i < n-1 && i < (size_t)sz && b[i] >= 32 && b[i] < 127 && b[i]) out[i]=b[i], i++;
    out[i] = 0;
}
static bool ptr_ok(uint64_t p) { return p > 0x100000000ULL && p < 0x40000000000ULL; }

// Cl1k Il2CppGetHandle (PageWalk from Cl1k decrypts.h)
static uint64_t gchandle(uint64_t h) {
    if (!h) return 0;
    uint64_t v1 = h & 0xFFFFFFFFFFFFE000ULL;
    uint8_t tb = 0;
    if (!v1 || r8(v1 + 0x20, &tb) || tb >= 4) return 0;  // PageType_Off = 0x20
    uint32_t cap = 0;
    if (r32(v1 + 0x1C, &cap)) return 0;  // PageSize_Off = 0x1C
    int64_t slot = (int64_t)(h - v1 - 0x28) >> 3;  // SlotOffset_Base = 0x28
    if (slot < 0 || (uint32_t)slot >= cap || cap > 0x1000000u) return 0;
    uint64_t bm = 0;
    if (r64(v1 + 0x10, &bm) || !ptr_ok(bm)) return 0;  // PageBitmap_Off = 0x10
    uint32_t bm32 = 0;
    if (r32(bm + 4 * ((uint32_t)slot >> 5), &bm32)) return 0;
    if (!((bm32 >> ((uint32_t)slot & 0x1F)) & 1)) return 0;
    uint64_t entry = v1 + 8 * ((uint32_t)slot + 5);  // Entry_Payload_Offset = 5
    uint64_t val = 0;
    if (r64(entry, &val)) return 0;
    if (tb > 1) return val;
    return ~val;
}

// Cl1k BaseNetworkableKey decrypt: ADD 0xB97F1AE1, ROL 29, ADD 0x32BEE2A5, XOR 0xE58A30D8
static uint64_t decrypt_bn_key(uint64_t hv) {
    uint32_t p[2]; memcpy(p, &hv, 8);
    for (int i = 0; i < 2; i++) {
        uint32_t v = p[i];
        v += 0xB97F1AE1u;
        v = (v << 29) | (v >> 3);
        v += 0x32BEE2A5u;
        v ^= 0xE58A30D8u;
        p[i] = v;
    }
    memcpy(&hv, p, 8);
    return hv;
}

// Cl1k DecryptList: ROL 10, XOR 0xF6BF245D, ROL 15, XOR 0x9BBD4311
static uint64_t decrypt_list(uint64_t hv) {
    uint32_t p[2]; memcpy(p, &hv, 8);
    for (int i = 0; i < 2; i++) {
        uint32_t v = p[i];
        v = (v << 10) | (v >> 22);
        v ^= 0xF6BF245Du;
        v = (v << 15) | (v >> 17);
        v ^= 0x9BBD4311u;
        p[i] = v;
    }
    memcpy(&hv, p, 8);
    return hv;
}

int main() {
    pid_t pid = 2541;
    task_for_pid(mach_task_self(), pid, &task);
    if (!task) { printf("task_for_pid failed\n"); return 1; }
    uint64_t K = 0x103a80990; // BaseNetworkable klass
    printf("[+] brute-force static_fields for klass 0x%llx\n", K);
    
    for (int sf_off = 0x80; sf_off <= 0x180; sf_off += 8) {
        uint64_t sf = 0;
        if (r64(K + sf_off, &sf) || !ptr_ok(sf)) continue;
        // Cl1k: wrapper at [sf + 0x08] (TypeInfo_StaticFieldsBridge)
        uint64_t wr = 0;
        if (r64(sf + 0x08, &wr)) continue;
        if (!ptr_ok(wr)) continue;
        // Read encrypted value at [wr + 0x18]
        uint64_t hv = 0;
        if (r64(wr + 0x18, &hv) || !hv) continue;
        
        // Try decrypt with BaseNetworkableKey
        uint64_t dec = decrypt_bn_key(hv);
        uint64_t entityRealm = gchandle(dec);
        if (!entityRealm) continue;
        
        // Cl1k: scan entityRealm + 0x08 .. + 0x58 for BufferLists
        int found_any = 0;
        for (int er_off = 0x08; er_off <= 0x58; er_off += 8) {
            uint64_t obj = 0;
            if (r64(entityRealm + er_off, &obj) || !ptr_ok(obj)) continue;
            uint64_t arr = 0;
            int cnt = 0;
            if (r64(obj + 0x10, &arr)) continue;  // BufferList_Array
            if (r32(obj + 0x18, (uint32_t*)&cnt)) continue;  // BufferList_Count
            if (cnt < 10 || cnt > 50000 || !ptr_ok(arr)) continue;
            // Validate: read 3 entries
            int valid = 0;
            for (int j = 0; j < 3 && j < cnt; j++) {
                uint64_t ent = 0;
                if (r64(arr + 0x28 + 8*j, &ent) || !ptr_ok(ent)) continue;
                uint64_t ek = 0;
                if (r64(ent, &ek) || !ptr_ok(ek)) continue;
                char name[64];
                cstr(ek + 0x10, name, 64);
                if (name[0] >= 'A' && name[0] <= 'Z') valid++;
            }
            if (valid >= 2) {
                printf("*** HIT sf@+0x%02x=0x%llx er@+0x%02x obj=0x%llx cnt=%d\n", sf_off, sf, er_off, obj, cnt);
                printf("    entityRealm=0x%llx\n", entityRealm);
                for (int j = 0; j < 5 && j < cnt; j++) {
                    uint64_t ent = 0;
                    if (r64(arr + 0x28 + 8*j, &ent)) break;
                    uint64_t ek = 0; r64(ent, &ek);
                    char name[64]; cstr(ek + 0x10, name, 64);
                    uint64_t sid = 0; r64(ent + 0x718, &sid);
                    printf("    ent[%d] 0x%llx \"%s\" sid=%llu\n", j, ent, name, sid);
                }
                found_any++;
            }
        }
        if (found_any) break;
    }
    printf("[+] done\n");
    return 0;
}
