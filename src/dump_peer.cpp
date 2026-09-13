// =============================================================================
// dump_peer.cpp — structured dump of remote player entry 0x690a6c0e0 (0x1000)
// + all heap pointers found, with vtable & position probes on each.
// =============================================================================
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>

static task_t g_task;
static bool rmem(uint64_t a, void* b, size_t s) {
    vm_size_t got = 0;
    return vm_read_overwrite(g_task, (vm_address_t)a, s, (vm_address_t)b, &got) == KERN_SUCCESS && (size_t)got == s;
}
static uint64_t r64(uint64_t a) { uint64_t v = 0; rmem(a, &v, 8); return v; }
static float rf(uint64_t a) { float v = 0; rmem(a, &v, 4); return v; }
static bool vptr(uint64_t p) { return p > 0x10000ULL && p < 0x7FFFFFFFFFFFULL; }
static bool in_world(float x, float y, float z) {
    if (!std::isfinite(x) || !std::isfinite(y) || !std::isfinite(z)) return false;
    return fabsf(x) < 4000 && fabsf(z) < 4000 && y > -100 && y < 1000;
}

const uint64_t OBJ = 0x690a6c0e0;

int main() {
    setvbuf(stdout, NULL, _IONBF, 0);
    pid_t pid = 0;
    pid_t pids[8192]; int np = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    for (int i = 0; i < np / (int)sizeof(pid_t); i++) {
        if (!pids[i]) continue; char path[PROC_PIDPATHINFO_MAXSIZE] = {};
        if (proc_pidpath(pids[i], path, sizeof(path)) > 0 && strstr(path, "RustClient")) { pid = pids[i]; break; }
    }
    if (!pid) { printf("[!] Rust not found\n"); return 1; }
    if (task_for_pid(mach_task_self(), pid, &g_task) != KERN_SUCCESS) { printf("[!] task_for_pid failed\n"); return 1; }
    printf("[+] PID=%d obj=0x%llx\n", pid, (unsigned long long)OBJ);

    std::vector<uint8_t> b(0x1000);
    if (!rmem(OBJ, b.data(), 0x1000)) { printf("[!] read failed\n"); return 1; }

    // 1) structured dump: qword + float triplets
    for (int o = 0; o < 0x1000; o += 0x20) {
        uint64_t q0, q1; memcpy(&q0, b.data() + o, 8); memcpy(&q1, b.data() + o + 8, 8);
        uint64_t q2, q3; memcpy(&q2, b.data() + o + 0x10, 8); memcpy(&q3, b.data() + o + 0x18, 8);
        char tag0 = ' ', tag1 = ' ', tag2 = ' ', tag3 = ' ';
        if (vptr(q0)) tag0 = 'P'; if (vptr(q1)) tag1 = 'P'; if (vptr(q2)) tag2 = 'P'; if (vptr(q3)) tag3 = 'P';
        float f0, f1, f2; memcpy(&f0, b.data() + o, 4); memcpy(&f1, b.data() + o + 4, 4); memcpy(&f2, b.data() + o + 8, 4);
        char wf = ' ';
        if (in_world(f0, f1, f2) && fabsf(f0) + fabsf(f2) > 100) wf = 'W';
        printf("+%04x: %c0x%016llx %c0x%016llx %c0x%016llx %c0x%016llx  f(%.1f,%.1f,%.1f)%c\n",
               o, tag0, (unsigned long long)q0, tag1, (unsigned long long)q1, tag2, (unsigned long long)q2, tag3, (unsigned long long)q3,
               f0, f1, f2, wf);
    }

    // 2) heap pointers in object -> probe vtable + possible positions
    printf("\n== heap ptr probes ==\n");
    int n = 0;
    for (int o = 0; o + 8 <= 0x1000; o += 8) {
        uint64_t p; memcpy(&p, b.data() + o, 8);
        if (!vptr(p) || p < 0x100000000ULL) continue;
        uint64_t v0 = r64(p);
        if (!vptr(v0) && !(v0 >> 40 == 0x1ff)) continue; // likely object (has vtable)
        float x = rf(p + 0x2F8), y = rf(p + 0x2F8 + 4), z = rf(p + 0x2F8 + 8);
        float x2 = rf(p + 0x1168), y2 = rf(p + 0x1168 + 4), z2 = rf(p + 0x1168 + 8);
        printf("  +0x%x -> 0x%llx [vt=0x%llx] pos2F8=%s pos1168=%s\n", o, (unsigned long long)p, (unsigned long long)v0,
               in_world(x, y, z) && fabsf(x) + fabsf(z) > 100 ? "(W)" : "-",
               in_world(x2, y2, z2) && fabsf(x2) + fabsf(z2) > 100 ? "(W)" : "-");
        if (++n > 40) break;
    }
    return 0;
}
