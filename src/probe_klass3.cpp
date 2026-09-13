// probe_klass3.cpp — find Il2CppClass by name string + back-reference (name_ptr @ klass+0x10)
// Chunked 4MB reads (same as daemon). Target: BaseNetworkable / BasePlayer klass addresses.
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <map>
#include <set>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <unistd.h>

static mach_port_t task;
static const char* TARGETS[] = { "BaseNetworkable", "BasePlayer", "BaseCombatEntity", "PlayerModel", "BaseEntity" };
static const int NT = 5;
static const uint64_t CHUNK = 4ULL * 1024 * 1024;

static int r64(uint64_t a, uint64_t* v) {
    mach_vm_size_t sz = 0;
    kern_return_t kr = mach_vm_read_overwrite(task, (mach_vm_address_t)a, 8, (mach_vm_address_t)v, &sz);
    return kr == KERN_SUCCESS && sz == 8 ? 0 : -1;
}

int main() {
    pid_t pid = 2541;
    task_for_pid(mach_task_self(), pid, &task);
    if (!task) { printf("task_for_pid failed\n"); return 1; }
    fprintf(stderr, "[+] Rust PID=%d scanning\n", pid);
    fflush(stderr);

    // pass 1: find string addresses in readable non-exec regions < 2GB
    std::vector<uint64_t> str_addrs[NT];
    std::vector<std::pair<uint64_t,uint64_t>> regions; // (addr, len)
    mach_vm_address_t addr = 0;
    mach_vm_size_t sz = 0;
    std::vector<uint8_t> buf(CHUNK);
    while (1) {
        mach_port_t objname = 0;
        mach_msg_type_number_t cnt2 = VM_REGION_BASIC_INFO_COUNT_64;
        vm_region_basic_info_data_64_t bi;
        kern_return_t kr = mach_vm_region(task, &addr, &sz, VM_REGION_BASIC_INFO_64,
                                          (vm_region_info_t)&bi, &cnt2, &objname);
        if (kr != KERN_SUCCESS) break;
        if (addr > 0x200000000ULL) break;
        if ((bi.protection & VM_PROT_READ) && !(bi.protection & VM_PROT_EXECUTE)) {
            regions.push_back({addr, sz});
            for (uint64_t off = 0; off < sz; off += CHUNK) {
                uint64_t want = std::min(CHUNK, sz - off);
                mach_vm_size_t got = 0;
                if (mach_vm_read_overwrite(task, addr + off, want, (mach_vm_address_t)buf.data(), &got) != KERN_SUCCESS || got != want)
                    continue;
                for (int t = 0; t < NT; t++) {
                    size_t L = strlen(TARGETS[t]);
                    for (size_t i = 0; i + L + 1 <= want; i++) {
                        if (memcmp(buf.data()+i, TARGETS[t], L+1) == 0) {
                            str_addrs[t].push_back(addr + off + i);
                            i += L;
                        }
                    }
                }
            }
        }
        addr += sz;
    }
    fprintf(stderr, "[+] regions=%zu\n", regions.size());
    for (int t = 0; t < NT; t++) {
        printf("strings \"%s\": %zu\n", TARGETS[t], str_addrs[t].size());
        for (auto a : str_addrs[t]) printf("    0x%llx\n", a);
    }
    fflush(stdout);

    // pass 2: back-reference — any qword in any region == a target string addr
    std::set<uint64_t> targets;
    for (int t = 0; t < NT; t++)
        for (auto a : str_addrs[t]) targets.insert(a);
    std::map<uint64_t, int> klass_found;
    for (auto& [ra, rsz] : regions) {
        for (uint64_t off = 0; off < rsz; off += CHUNK) {
            uint64_t want = std::min(CHUNK, rsz - off);
            mach_vm_size_t got = 0;
            if (mach_vm_read_overwrite(task, ra + off, want, (mach_vm_address_t)buf.data(), &got) != KERN_SUCCESS || got != want)
                continue;
            for (uint64_t i = 0; i + 8 <= want; i += 8) {
                uint64_t q;
                memcpy(&q, buf.data()+i, 8);
                if (targets.count(q)) {
                    uint64_t klass = ra + off + i - 0x10;
                    for (int t = 0; t < NT; t++)
                        for (auto sa : str_addrs[t])
                            if (sa == q) klass_found[klass] = t;
                }
            }
        }
    }
    printf("[+] klass candidates: %zu\n", klass_found.size());
    for (auto& [k, t] : klass_found) {
        uint64_t sf = 0, parent = 0;
        r64(k + 0xb8, &sf);
        r64(k + 0x8, &parent);
        printf("KLASS 0x%llx \"%s\" static_fields=0x%llx parent=0x%llx\n", k, TARGETS[t], sf, parent);
    }
    return 0;
}
