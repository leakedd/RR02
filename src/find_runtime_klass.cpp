// find_runtime_klass.cpp — scan heap for Il2CppClass with name "BaseNetworkable" @+0x10
// AND static_fields @+0xB8 != 0 (runtime initialized klass, needed for entity list)
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <unistd.h>

static mach_port_t task;
static const char* TARGET = "BaseNetworkable";
static int r64(uint64_t a, uint64_t* v) {
    mach_vm_size_t sz = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, (mach_vm_address_t)a, 8, (mach_vm_address_t)v, &sz);
    return kr == KERN_SUCCESS && sz == 8 ? 0 : -1;
}
static bool ptr_ok(uint64_t p) { return p > 0x100000000ULL && p < 0x40000000000ULL; }

int main() {
    pid_t pid = 2541;
    task_for_pid(mach_task_self(), pid, &task);
    if (!task) { printf("task_for_pid failed\n"); return 1; }
    printf("[+] scanning for runtime klass \"%s\" with non-null static_fields\n", TARGET);

    // First: find ALL "BaseNetworkable" strings
    std::vector<uint64_t> strings;
    std::vector<uint8_t> buf(4 * 1024 * 1024);
    mach_vm_address_t addr = 0;
    mach_vm_size_t sz = 0;
    size_t L = strlen(TARGET);
    while (1) {
        mach_port_t objname = 0;
        mach_msg_type_number_t cnt2 = VM_REGION_BASIC_INFO_COUNT_64;
        vm_region_basic_info_data_64_t bi;
        kern_return_t kr = mach_vm_region(task, &addr, &sz, VM_REGION_BASIC_INFO_64,
                                          (vm_region_info_t)&bi, &cnt2, &objname);
        if (kr != KERN_SUCCESS) break;
        if (!(bi.protection & VM_PROT_READ) || bi.protection & VM_PROT_EXECUTE) { addr += sz; continue; }
        if (sz > 512ULL*1024*1024) { addr += sz; continue; }
        for (uint64_t o = 0; o < sz; o += buf.size()) {
            uint64_t tr = std::min((uint64_t)buf.size(), sz - o);
            mach_vm_size_t got = 0;
            if (mach_vm_read_overwrite(task, addr+o, tr, (mach_vm_address_t)buf.data(), &got) != KERN_SUCCESS) break;
            for (size_t i = 0; i + L + 1 <= got; i++) {
                if (memcmp(buf.data()+i, TARGET, L+1) == 0) {
                    strings.push_back(addr + o + i);
                    i += L;
                }
            }
        }
        addr += sz;
        if (addr > 0x200000000ULL) break;
    }
    printf("[+] %zu strings found\n", strings.size());

    // Now scan heap regions for qwords == any string addr → klass = qword_addr - 0x10
    // Check [klass+0xB8] non-null
    addr = 0; sz = 0;
    int found = 0;
    while (1) {
        mach_port_t objname = 0;
        mach_msg_type_number_t cnt2 = VM_REGION_BASIC_INFO_COUNT_64;
        vm_region_basic_info_data_64_t bi;
        kern_return_t kr = mach_vm_region(task, &addr, &sz, VM_REGION_BASIC_INFO_64,
                                          (vm_region_info_t)&bi, &cnt2, &objname);
        if (kr != KERN_SUCCESS) break;
        if (!(bi.protection & VM_PROT_READ) || bi.protection & VM_PROT_EXECUTE) { addr += sz; continue; }
        if (sz > 512ULL*1024*1024) { addr += sz; continue; }
        for (uint64_t o = 0; o < sz; o += buf.size()) {
            uint64_t tr = std::min((uint64_t)buf.size(), sz - o);
            mach_vm_size_t got = 0;
            if (mach_vm_read_overwrite(task, addr+o, tr, (mach_vm_address_t)buf.data(), &got) != KERN_SUCCESS) break;
            for (size_t i = 0; i + 8 <= got; i += 8) {
                uint64_t q;
                memcpy(&q, buf.data()+i, 8);
                for (uint64_t sa : strings) {
                    if (q != sa) continue;
                    uint64_t klass = addr + o + i - 0x10;
                    if (!ptr_ok(klass)) continue;
                    uint64_t sf = 0;
                    r64(klass + 0xB8, &sf);
                    if (!ptr_ok(sf)) continue;
                    // ALSO check that the klass name ptr points to this string (double-verify)
                    uint64_t np = 0;
                    r64(klass + 0x10, &np);
                    printf("RUNTIME KLASS 0x%llx sf=0x%llx name_at+0x10=0x%llx\n", klass, sf, np);
                    fflush(stdout);
                    if (++found >= 5) goto done;
                }
            }
        }
        addr += sz;
    }
done:
    printf("[+] found %d runtime BaseNetworkable klasses with sf!=0\n", found);
    return 0;
}
