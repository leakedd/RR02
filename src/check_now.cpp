// =============================================================================
// check_now.cpp — re-read SID@+0x1b0 for all 9 player objs (proper task_for_pid)
// =============================================================================
#include <cstdio>
#include <cstdint>
#include <mach/mach.h>
#include <unistd.h>

static mach_port_t task;

static uint64_t r64(uint64_t a) {
    uint64_t v = 0; mach_msg_type_number_t sz = 0;
    vm_read(task, (vm_address_t)a, 8, (vm_offset_t*)&v, &sz);
    return v;
}

int main() {
    if (task_for_pid(mach_task_self(), 2541, &task) != KERN_SUCCESS) {
        printf("task_for_pid failed\n"); return 1;
    }
    uint64_t objs[] = {0x68aaec980, 0x690a6c0e0, 0x690a17740, 0x7af7d84c0, 0x68531e2a0, 0x6887a7d00, 0x68985f980, 0x690aaace0, 0x6869b3060};
    const char* names[] = {"user", "p1", "p2", "p3", "p4", "p5", "p6", "p7", "p8"};
    for (int i = 0; i < 9; i++) {
        uint64_t v0 = r64(objs[i]);
        uint64_t sid = r64(objs[i] + 0x1b0);
        uint64_t sid2 = r64(objs[i] + 0x718);
        float x = 0, y = 0, z = 0; { uint32_t a, b, c; mach_msg_type_number_t s = 0; vm_read(task, (vm_address_t)(objs[i] + 0x1168), 12, (vm_offset_t*)&a, &s); vm_read(task, (vm_address_t)(objs[i] + 0x116c), 4, (vm_offset_t*)&b, &s); vm_read(task, (vm_address_t)(objs[i] + 0x1170), 4, (vm_offset_t*)&c, &s); __builtin_memcpy(&x, &a, 4); __builtin_memcpy(&y, &b, 4); __builtin_memcpy(&z, &c, 4); }
        printf("%-5s obj=0x%llx [0]=0x%llx SID@1b0=%llu pos1168=(%.1f,%.1f,%.1f)\n",
            names[i], (unsigned long long)objs[i],
            (unsigned long long)v0,
            (unsigned long long)sid, x, y, z);
    }
    return 0;
}
