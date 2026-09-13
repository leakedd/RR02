// dump_local.cpp — deep-dump the BasePlayer candidate found by userID@+0x718 scan
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <mach/mach.h>
#include <mach/mach_vm.h>

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
static int rbuf(uint64_t a, void* b, size_t n) {
    mach_vm_size_t sz = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, (mach_vm_address_t)a, n, (mach_vm_address_t)b, &sz);
    return kr == KERN_SUCCESS && sz == n ? 0 : -1;
}

// read Unity string: [p+0x10]=length, [p+0x14]=utf16
static void dump_str(uint64_t p, const char* label) {
    if (!p) { printf("    %-24s = (null)\n", label); return; }
    uint32_t len = 0;
    if (r32(p + 0x10, &len) || len > 64) { printf("    %-24s = ptr 0x%llx len?=%u\n", label, p, len); return; }
    uint16_t buf[64];
    if (rbuf(p + 0x14, buf, len * 2)) { printf("    %-24s = read fail\n", label); return; }
    char out[200]; int n = 0;
    for (uint32_t i = 0; i < len && i < 63; i++) {
        uint16_t c = buf[i];
        if (c >= 32 && c < 127) out[n++] = (char)c;
        else out[n++] = '?';
    }
    out[n] = 0;
    printf("    %-24s = \"%s\" (len=%u)\n", label, out, len);
}

// scan float triples in [a, a+n) matching target within eps, print offsets
static void find_pos(uint64_t a, size_t n, float tx, float ty, float tz, float eps, const char* label) {
    std::vector<uint8_t> buf(n);
    if (rbuf(a, buf.data(), n)) { printf("    %s: read fail\n", label); return; }
    int hits = 0;
    for (size_t off = 0; off + 12 <= n && hits < 8; off += 4) {
        float x, y, z;
        memcpy(&x, buf.data()+off, 4);
        memcpy(&y, buf.data()+off+4, 4);
        memcpy(&z, buf.data()+off+8, 4);
        if (fabsf(x-tx) < eps && fabsf(y-ty) < eps && fabsf(z-tz) < eps)
            printf("    %s: pos match @ +0x%zx = (%.2f, %.2f, %.2f)\n", label, off, x, y, z), hits++;
    }
    if (!hits) printf("    %s: no match\n", label);
}

int main(int argc, char** argv) {
    pid_t pid = 2541;
    task_for_pid(mach_task_self(), pid, &task);
    if (!task) { printf("task_for_pid failed\n"); return 1; }
    printf("[+] Rust PID=%d\n", pid);

    uint64_t obj = 0x68c27b958; // BasePlayer candidate (SID local @+0x718)
    uint64_t v = 0, pm = 0, tmp = 0;
    float f[3];
    r64(obj+0x00, &v);   printf("[obj+0x00] vtable       = 0x%llx\n", v);
    r64(obj+0x718, &tmp); printf("[obj+0x718] userID       = %llu\n", tmp);
    r64(obj+0x340, &pm);  printf("[obj+0x340] playerModel  = 0x%llx\n", pm);
    if (pm) {
        r64(pm+0x00, &v); printf("[pm+0x00]  vtable       = 0x%llx\n", v);
        rbuf(pm+0x2F8, f, 12); printf("[pm+0x2F8]  pos(UC)      = (%.2f, %.2f, %.2f)\n", f[0], f[1], f[2]);
        rbuf(pm+0x31C, f, 12); printf("[pm+0x31C]  velocity(UC) = (%.2f, %.2f, %.2f)\n", f[0], f[1], f[2]);
        rbuf(pm+0x338, f, 12); printf("[pm+0x338]  rotation(UC) = (%.2f, %.2f, %.2f)\n", f[0], f[1], f[2]);
        // scan whole PlayerModel alloc for the known local pos
        find_pos(pm, 0x800, -147.31f, 30.99f, 1517.65f, 0.05f, "pm");
    }
    r64(obj+0x1168, &tmp); // not pos ptr, read floats
    rbuf(obj+0x1168, f, 12); printf("[obj+0x1168] pos(direct) = (%.2f, %.2f, %.2f)\n", f[0], f[1], f[2]);
    rbuf(obj+0x10e0, f, 12); printf("[obj+0x10e0] alt pos     = (%.2f, %.2f, %.2f)\n", f[0], f[1], f[2]);
    r64(obj+0x7a0, &tmp); printf("[obj+0x7a0]  eyes(UC)    = 0x%llx\n", tmp);
    r64(obj+0x4b0, &tmp); printf("[obj+0x4b0]  inv(UC)     = 0x%llx\n", tmp);
    r64(obj+0x3a0, &tmp); printf("[obj+0x3a0]  meta(UC)    = 0x%llx\n", tmp);
    r64(obj+0x520, &tmp); printf("[obj+0x520]  mv(UC)      = 0x%llx\n", tmp);
    r32(obj+0x6d0, (uint32_t*)&tmp); printf("[obj+0x6d0]  flags(UC)   = 0x%llx\n", tmp);
    r64(obj+0x2d0, &tmp); printf("[obj+0x2d0]  modelState  = 0x%llx\n", tmp);
    r64(obj+0x390, &tmp); dump_str(tmp, "displayName(0x390)");
    r64(obj+0x4e8, &tmp); dump_str(tmp, "UserIDString(0x4e8)");
    r64(obj+0x300, &tmp); dump_str(tmp, "userIDStr(0x300)");
    r64(obj+0x598, &tmp); dump_str(tmp, "UserIDString(0x598)");
    // find local pos anywhere in the whole object (first 0x2000)
    find_pos(obj, 0x2000, -147.31f, 30.99f, 1517.65f, 0.05f, "obj");
    return 0;
}
