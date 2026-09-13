// RR02/test_dump.cpp — Test offsets from Bigpapa1's July 18 dump
// BasePlayer +0x700 = userID, +0x6F0 = player_model, +0x2D8 = name
// PlayerModel +0x2F8 = position
// Klass = GameAssembly_base + 0xFCCA7D0

#include <cstdio>
#include <cstdint>
#include <cmath>
#include <cstring>
#include <vector>
#include <string>
#include <algorithm>
#include <unistd.h>
#include <mach/mach.h>
#include <libproc.h>

static task_t g_task;
static bool read_mem(uint64_t addr, void* buf, size_t size) {
    vm_size_t got = 0;
    return vm_read_overwrite(g_task, (vm_address_t)addr, size, (vm_address_t)buf, &got) == KERN_SUCCESS && got == size;
}
static uint64_t r64(uint64_t a) { uint64_t v=0; read_mem(a,&v,8); return v; }
static float rf(uint64_t a) { float v=0; read_mem(a,&v,4); return v; }
static bool vptr(uint64_t p) { return p>0x100000ULL&&p<0x800000000000ULL; }

static std::string read_str(uint64_t addr) {
    uint64_t str = r64(addr);
    if (!vptr(str)) return "";
    uint32_t len; read_mem(str+0x10,&len,4);
    if (len==0||len>64) return "";
    std::string out;
    for (uint32_t i=0;i<len&&i<63;i++) {
        uint16_t c; read_mem(str+0x14+i*2,&c,2);
        if (c==0) break;
        if (c>31&&c<127) out+=(char)c; else out+='?';
    }
    return out;
}

static pid_t find_rust() {
    pid_t pids[4096]; int n=proc_listpids(PROC_ALL_PIDS,0,pids,sizeof(pids));
    for (int i=0;i<n/(int)sizeof(pid_t);i++) {
        char p[1024]; if(proc_pidpath(pids[i],p,sizeof(p))>0&&strstr(p,"RustClient")) return pids[i];
    }
    return -1;
}

int main() {
    printf("=== RR02 Test Dump Offsets ===\n");
    pid_t pid = find_rust();
    if (pid<0) { printf("[!] Rust not found\n"); return 1; }
    if (task_for_pid(mach_task_self(),pid,&g_task)!=0) { printf("[!] t_f_p\n"); return 1; }

    // Find GameAssembly base via executable region filename
    vm_address_t a=0; vm_size_t sz; vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt; mach_port_t obj;
    uint64_t ga_base=0;
    while(true){
        cnt=VM_REGION_BASIC_INFO_COUNT_64;
        if(vm_region_64(g_task,&a,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&cnt,&obj)) break;
        if(info.protection&VM_PROT_EXECUTE) {
            char name[256];
            if(proc_regionfilename(pid,a,name,sizeof(name))>0 && strstr(name,"RustClient")) {
                ga_base=a; break;
            }
        }
        a+=sz;
    }
    printf("[+] GameAssembly base: 0x%llx\n", ga_base);
    if(!ga_base){printf("[!] Can't find GA\n"); return 1;}

    // Compute klass from RVA
    uint64_t klass = ga_base + 0xFCCA7D0;
    printf("[+] BasePlayer klass: 0x%llx (GA_base+0xFCCA7D0)\n", klass);

    // Verify the klass by reading its name pointer
    uint64_t name_ptr = r64(klass + 0x10);
    printf("[+] Klass name_ptr: 0x%llx\n", name_ptr);
    if(vptr(name_ptr)) {
        char nb[64]={0};
        read_mem(name_ptr, nb, 32);
        printf("[+] Klass name: %s\n", nb);
    }

    // Scan ALL writable memory for objects with this klass at offset 0
    struct Rg { uint64_t s,e; };
    static Rg regs[128000]; int rc=0;
    a=0;
    while(rc<128000){
        cnt=VM_REGION_BASIC_INFO_COUNT_64;
        if(vm_region_64(g_task,&a,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&cnt,&obj))break;
        if((info.protection&VM_PROT_READ)&&(info.protection&VM_PROT_WRITE)&&sz<=256*1024*1024) regs[rc++]={(uint64_t)a,(uint64_t)a+sz};
        a+=sz;
    }
    printf("[+] %d writable regions\n", rc);

    static uint8_t buf[8*1024*1024];
    std::vector<uint64_t> bps;

    for(int ri=0;ri<rc&&bps.size()<200;ri++){
        for(uint64_t off=0;off<regs[ri].e-regs[ri].s;off+=8*1024*1024){
            uint64_t ch=regs[ri].e-regs[ri].s-off; if(ch>8*1024*1024)ch=8*1024*1024;
            vm_size_t got=0;
            if(vm_read_overwrite(g_task,(vm_address_t)(regs[ri].s+off),ch,(vm_address_t)buf,&got))break;
            for(size_t i=0;i+8<=got;i+=8){
                uint64_t v; memcpy(&v,buf+i,8);
                if(v!=klass) continue;
                bps.push_back(regs[ri].s+off+i);
            }
        }
    }

    printf("[+] Found %zu objects with BasePlayer klass\n", bps.size());

    if(bps.empty()){printf("[!] No BasePlayer objects found\n"); return 1;}

    // Test the dump offsets
    printf("\n=== Testing dump offsets ===\n");
    printf("%-12s %-24s %-24s %-10s\n", "SID", "Name(2D8)", "Pos(PM+2F8)", "PM(6F0)");

    int valid_sid=0, valid_name=0, valid_pos=0, valid_pm=0;

    for(size_t i=0;i<std::min(bps.size(),(size_t)30);i++){
        uint64_t bp = bps[i];
        uint64_t sid = r64(bp + 0x700);
        bool sid_ok = (sid >= 76561197900000000ULL && sid < 76561300000000000ULL);

        std::string name = read_str(bp + 0x2D8);
        bool name_ok = !name.empty() && name.size()>1;

        uint64_t pm = r64(bp + 0x6F0);
        bool pm_ok = vptr(pm);

        float px=0,py=0,pz=0; bool pos_ok=false;
        if(pm_ok){
            px=rf(pm+0x2F8); py=rf(pm+0x2F8+4); pz=rf(pm+0x2F8+8);
            pos_ok = std::isfinite(px)&&std::isfinite(py)&&std::isfinite(pz)&&
                     px>-5000&&px<5000&&pz>-5000&&pz<5000&&py>-200&&py<2000&&(px!=0||pz!=0);
        }

        if(sid_ok) valid_sid++;
        if(name_ok) valid_name++;
        if(pm_ok) valid_pm++;
        if(pos_ok) valid_pos++;

        char pos_s[64], sid_s[20];
        snprintf(pos_s,sizeof(pos_s),"(%.1f,%.1f,%.1f)",px,py,pz);
        snprintf(sid_s,sizeof(sid_s),"%llu",sid%100000);

        printf("%-12s %-24s %-24s %-10s\n",
               sid_ok ? sid_s : "BAD",
               name_ok ? name.c_str() : (name.empty() ? "empty" : name.c_str()),
               pos_ok ? pos_s : (pm_ok ? "(0,0,0)" : "NO PM"),
               pm_ok ? "OK" : "BAD");
    }

    printf("\n=== Summary ===\n");
    printf("  userID (0x700):  %d/%zu\n", valid_sid, std::min(bps.size(),(size_t)30));
    printf("  name (0x2D8):    %d/%zu\n", valid_name, std::min(bps.size(),(size_t)30));
    printf("  PM (0x6F0):      %d/%zu\n", valid_pm, std::min(bps.size(),(size_t)30));
    printf("  pos (PM+0x2F8):  %d/%zu\n", valid_pos, std::min(bps.size(),(size_t)30));

    return 0;
}
