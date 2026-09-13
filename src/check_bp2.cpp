// =============================================================================
// check_bp2.cpp — deep-check candidate real BasePlayer (SID@0x718) + container
// =============================================================================
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>

static task_t g_task;
static bool rmem(uint64_t a, void* b, size_t s) {
    vm_size_t got = 0;
    return vm_read_overwrite(g_task, (vm_address_t)a, s, (vm_address_t)b, &got) == KERN_SUCCESS && (size_t)got == s;
}
static uint64_t r64(uint64_t a) { uint64_t v = 0; rmem(a, &v, 8); return v; }
static float rf(uint64_t a) { float v = 0; rmem(a, &v, 4); return v; }
static bool is_sid(uint64_t v) { return v >= 76561197960265728ULL && v < 76561202255233023ULL; }

static void dump_pos(const char* tag, uint64_t a) {
    float x = rf(a), y = rf(a + 4), z = rf(a + 8);
    bool ok = std::isfinite(x) && std::isfinite(y) && std::isfinite(z) && fabsf(x) < 4000 && fabsf(z) < 4000 && y > -100 && y < 1000;
    printf("    %-28s = (%.2f, %.2f, %.2f)%s\n", tag, x, y, z, ok ? "  <== WORLD" : "");
}

int main() {
    pid_t pids[8192]; int n = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    for (int i = 0; i < n / (int)sizeof(pid_t); i++) {
        if (!pids[i]) continue; char path[PROC_PIDPATHINFO_MAXSIZE] = {};
        if (proc_pidpath(pids[i], path, sizeof(path)) > 0 && strstr(path, "RustClient")) {
            task_for_pid(mach_task_self(), pids[i], &g_task);
            printf("[+] Rust PID=%d\n", pids[i]);
            break;
        }
    }
    if (!g_task) return 1;

    // Candidate real BasePlayer: SID was found at 0x64b899028 -> base = hit - 0x718
    const uint64_t B = 0x64b899028ULL - 0x718ULL;
    printf("\n=== B: real-BasePlayer candidate 0x%llx (SID@+0x718) ===\n", (unsigned long long)B);
    printf("    [B+0x00] vtable   = 0x%llx\n", (unsigned long long)r64(B));
    printf("    [B+0x10]          = 0x%llx\n", (unsigned long long)r64(B + 0x10));
    printf("    [B+0x1b0]         = %llu (sid? %s)\n", r64(B + 0x1b0), is_sid(r64(B + 0x1b0)) ? "yes" : "no");
    printf("    [B+0x718] userID  = %llu (sid? %s)\n", r64(B + 0x718), is_sid(r64(B + 0x718)) ? "yes" : "no");
    printf("    [B+0x340] playerModel = 0x%llx\n", (unsigned long long)r64(B + 0x340));
    uint64_t pm = r64(B + 0x340);
    if (pm > 0x10000 && pm < 0x7FFFFFFFFFFFULL) {
        printf("    [PM+0x00] vtable = 0x%llx\n", (unsigned long long)r64(pm));
        dump_pos("[PM+0x2F8] position", pm + 0x2F8);
        dump_pos("[PM+0x31C] velocity", pm + 0x31C);
    }
    // eyes (wrapped) raw
    printf("    [B+0x7A0] eyes    = 0x%llx\n", (unsigned long long)r64(B + 0x7A0));
    uint64_t eyes = r64(B + 0x7A0);
    if (eyes > 0x10000 && eyes < 0x7FFFFFFFFFFFULL) {
        printf("    [eyes+0x10]      = 0x%llx\n", (unsigned long long)r64(eyes + 0x10));
        printf("    [eyes+0x18] hval = 0x%llx\n", (unsigned long long)r64(eyes + 0x18));
    }
    // movement
    printf("    [B+0x520] movement = 0x%llx\n", (unsigned long long)r64(B + 0x520));
    uint64_t mv = r64(B + 0x520);
    if (mv > 0x10000 && mv < 0x7FFFFFFFFFFFULL) {
        dump_pos("[mv+0x130] velocity", mv + 0x130);
    }

    // Container A (daemon's object): does it point at B anywhere?
    const uint64_t A = 0x68aaec980ULL;
    printf("\n=== A: container 0x%llx (SID@+0x1b0) ===\n", (unsigned long long)A);
    printf("    [A+0x00] = 0x%llx\n", (unsigned long long)r64(A));
    printf("    [A+0x10] = 0x%llx\n", (unsigned long long)r64(A + 0x10));
    printf("    [A+0x340] = 0x%llx\n", (unsigned long long)r64(A + 0x340));
    printf("    [A+0x718] = %llu (sid? %s)\n", r64(A + 0x718), is_sid(r64(A + 0x718)) ? "yes" : "no");
    // scan A's first 0x400 qwords for pointers to B
    int refs = 0;
    for (int off = 0; off + 8 <= 0x2000; off += 8) {
        if (r64(A + off) == B) { printf("    [A+0x%03x] -> B (0x%llx) !!\n", off, (unsigned long long)B); refs++; }
    }
    printf("    refs to B in A[0..0x2000]: %d\n", refs);
    // user pos candidate on A
    dump_pos("[A+0x1168] cand pos", A + 0x1168);
    return 0;
}
