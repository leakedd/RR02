// test_uc4.cpp — follow klass chain from local object to BaseNetworkable static fields,
// then try UC decrypt (build 24614784) + Il2CppGetHandle to resolve the entity list.
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
static int rbuf(uint64_t a, void* b, size_t n) {
    mach_vm_size_t sz = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, (mach_vm_address_t)a, n, (mach_vm_address_t)b, &sz);
    return kr == KERN_SUCCESS && sz == n ? 0 : -1;
}
static void klass_name(uint64_t k, char* out, size_t n) {
    out[0] = 0;
    if (!k) return;
    uint64_t np = 0;
    if (r64(k + 0x10, &np) || !np) { snprintf(out, n, "<?>"); return; }
    uint8_t tmp[64];
    if (rbuf(np, tmp, 63)) { snprintf(out, n, "<unreadable>"); return; }
    size_t i = 0;
    while (i < 62 && tmp[i] >= 32 && tmp[i] < 127) { out[i] = tmp[i]; i++; }
    out[i] = 0;
}

static int r32(uint64_t a, uint32_t* v) {
    mach_vm_size_t sz = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, (mach_vm_address_t)a, 4, (mach_vm_address_t)v, &sz);
    return kr == KERN_SUCCESS && sz == 4 ? 0 : -1;
}
// Il2CppGetHandle — from UC thread (gchandle_get_target equivalent)
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
// UC decrypts (build 24614784)
static uint64_t dec_rounds(uint64_t rax, int mode) {
    uint32_t p[2]; memcpy(p, &rax, 8);
    for (int i = 0; i < 2; i++) {
        uint32_t v = p[i];
        if (mode == 0) { // client_entities: ROL31, ADD 0x8F7F58E3, ROL31, XOR 0x64DE867F
            v = (v << 31) | (v >> 1);
            v += 0x8F7F58E3u;
            v = (v << 31) | (v >> 1);
            v ^= 0x64DE867Fu;
        } else { // entity_list: ADD 0x0374D4FA, ROL27, XOR 0x5DD1D7B5, SUB 0x10D77418
            v += 0x0374D4FAu;
            v = (v << 27) | (v >> 5);
            v ^= 0x5DD1D7B5u;
            v -= 0x10D77418u;
        }
        p[i] = v;
    }
    memcpy(&rax, p, 8);
    return rax;
}

int main() {
    pid_t pid = 2541;
    task_for_pid(mach_task_self(), pid, &task);
    if (!task) { printf("task_for_pid failed\n"); return 1; }
    printf("[+] Rust PID=%d\n", pid);

    uint64_t obj = 0x68aaec980; // known local object (pos verified @+0x1168)
    uint64_t klass = 0;
    r64(obj, &klass);
    char name[64];
    klass_name(klass, name, 64);
    printf("[obj] 0x%llx klass=0x%llx name=\"%s\"\n", obj, klass, name);

    // walk parent chain up to 8 levels
    uint64_t k = klass;
    for (int i = 0; i < 8 && k; i++) {
        uint64_t parent = 0, sf = 0;
        r64(k + 0x8, &parent);
        r64(k + 0xb8, &sf);
        klass_name(k, name, 64);
        printf("  klass[%d] 0x%llx name=\"%s\" parent=0x%llx static_fields=0x%llx\n", i, k, name, parent, sf);
        if (strstr(name, "BaseNetworkable") || strstr(name, "BasePlayer") || strstr(name, "BaseEntity")) {
            // try entity list path: [sf+0x20] wrapper
            uint64_t wr = 0;
            if (sf && !r64(sf + 0x20, &wr)) {
                printf("    [sf+0x20] wrapper = 0x%llx\n", wr);
                uint64_t val = 0; uint8_t tb = 0xff;
                if (wr) {
                    r64(wr + 0x18, &val);
                    r8(wr + 0x10, &tb);
                    printf("    [wr+0x18] val = 0x%llx  [wr+0x10] type = 0x%02x\n", val, tb);
                    for (int m = 0; m < 2; m++) {
                        uint64_t dec = dec_rounds(val, m);
                        uint64_t list = il2cpp_get_handle(dec);
                        printf("    mode%d: dec=0x%llx handle->0x%llx\n", m, dec, list);
                        if (list) {
                            uint64_t items = 0; uint32_t cnt = 0;
                            r64(list + 0x10, &items);
                            r32(list + 0x18, &cnt);
                            printf("      list items=0x%llx count=%u\n", items, cnt);
                            if (items && cnt < 0x10000) {
                                for (uint32_t j = 0; j < cnt && j < 12; j++) {
                                    uint64_t ent = 0;
                                    if (r64(items + 8 * j, &ent) && r64(items + 0x20 + 8 * j, &ent)) break;
                                    uint64_t ek = 0; char en[64];
                                    r64(ent, &ek);
                                    klass_name(ek, en, 64);
                                    uint64_t sid = 0;
                                    r64(ent + 0x718, &sid);
                                    printf("      ent[%u] 0x%llx klass=0x%llx \"%s\" sid=0x%llx\n", j, ent, ek, en, sid);
                                }
                            }
                        }
                    }
                }
            }
        }
        k = parent;
    }
    return 0;
}
