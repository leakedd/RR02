// test_uc6.cpp — brute-force the ClientEntities path on macOS:
// klass BaseNetworkable 0x103a80990 -> static_fields at various offsets ->
// wrapper at sf+off -> decrypt client_entities (UC constants) -> Il2CppGetHandle -> List
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
static int r8(uint64_t a, uint8_t* v) {
    mach_vm_size_t sz = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, (mach_vm_address_t)a, 1, (mach_vm_address_t)v, &sz);
    return kr == KERN_SUCCESS && sz == 1 ? 0 : -1;
}
static int r32(uint64_t a, uint32_t* v) {
    mach_vm_size_t sz = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, (mach_vm_address_t)a, 4, (mach_vm_address_t)v, &sz);
    return kr == KERN_SUCCESS && sz == 4 ? 0 : -1;
}
static bool ptr_ok(uint64_t p) { return p > 0x100000000ULL && p < 0x40000000000ULL; }

// Il2CppGetHandle — from UC thread (gchandle_get_target)
static uint64_t il2cpp_get_handle(uint64_t h) {
    if (!h) return 0;
    uint64_t v1 = h & 0xFFFFFFFFFFFFE000ULL;
    uint8_t tb = 0;
    if (!v1 || r8(v1 + 32, &tb) || tb >= 4) return 0;
    uint32_t cap = 0;
    if (r32(v1 + 28, &cap)) return 0;
    uint64_t v3 = (h - v1 - 40) >> 3;
    if (v3 >= cap || cap > 0x1000000u) return 0;
    uint64_t bm = 0;
    if (r64(v1 + 16, &bm) || !bm) return 0;
    uint32_t bm32 = 0;
    if (r32(bm + 4 * (v3 >> 5), &bm32)) return 0;
    if (!((bm32 >> (v3 & 0x1F)) & 1)) return 0;
    uint64_t slot = v1 + 8 * (v3 + 5);
    if (tb > 1) { uint64_t p = 0; if (r64(slot, &p)) return 0; return p; }
    uint32_t p32 = 0; if (r32(slot, &p32)) return 0;
    return (uint64_t)(~p32);
}

// decrypt client_entities (build 24614784): ROL31, ADD 0x8F7F58E3, ROL31, XOR 0x64DE867F
static uint64_t dec_client_entities(uint64_t rax) {
    uint32_t p[2]; memcpy(p, &rax, 8);
    for (int i = 0; i < 2; i++) {
        uint32_t v = p[i];
        v = (v << 31) | (v >> 1);
        v += 0x8F7F58E3u;
        v = (v << 31) | (v >> 1);
        v ^= 0x64DE867Fu;
        p[i] = v;
    }
    memcpy(&rax, p, 8);
    return rax;
}

int main() {
    pid_t pid = 2541;
    task_for_pid(mach_task_self(), pid, &task);
    if (!task) { printf("task_for_pid failed\n"); return 1; }
    const uint64_t K = 0x103a80990; // BaseNetworkable klass (name verified)
    printf("[+] BaseNetworkable klass 0x%llx — brute force static_fields+wrapper\n", K);

    for (int sf_off = 0x90; sf_off <= 0xf8; sf_off += 8) {
        uint64_t sf = 0;
        if (r64(K + sf_off, &sf) || !ptr_ok(sf)) continue;
        for (int w_off = 0x0; w_off <= 0x40; w_off += 8) {
            uint64_t wr = 0;
            if (r64(sf + w_off, &wr) || !ptr_ok(wr)) continue;
            uint8_t tb = 0xff;
            uint64_t val = 0;
            r8(wr + 0x10, &tb);
            r64(wr + 0x18, &val);
            if (!val) continue;
            uint64_t dec = dec_client_entities(val);
            uint64_t list = il2cpp_get_handle(dec);
            if (!list) continue;
            uint64_t items = 0;
            uint32_t cnt = 0;
            r64(list + 0x10, &items);
            r32(list + 0x18, &cnt);
            if (cnt > 0 && cnt < 0x10000 && ptr_ok(items)) {
                printf("*** HIT sf@+0x%02x wr@+0x%02x wr=0x%llx tb=0x%02x val=0x%llx dec=0x%llx\n",
                       sf_off, w_off, wr, tb, val, dec);
                printf("    list=0x%llx items=0x%llx count=%u\n", list, items, cnt);
                for (uint32_t j = 0; j < cnt && j < 10; j++) {
                    uint64_t ent = 0;
                    if (r64(items + 8 * j, &ent)) break;
                    uint64_t ek = 0;
                    r64(ent, &ek);
                    uint64_t sid = 0;
                    r64(ent + 0x718, &sid);
                    printf("    ent[%u] 0x%llx klass=0x%llx sid=0x%llx\n", j, ent, ek, sid);
                }
                return 0;
            }
        }
    }
    printf("[+] no wrapper found with UC constants — macOS differs\n");
    return 0;
}
