// RR02/entitylist.cpp — Analyze the entity list structure
// SteamIDs are at 0x119f106xx, spaced by 0x10 (16 bytes)
// Each entry might be: {entity_ptr, steamID} or {steamID, entity_ptr}

#include <cstdio>
#include <cstdint>
#include <cmath>
#include <vector>
#include <unistd.h>
#include <mach/mach.h>
#include <libproc.h>

static task_t g_task;
static bool rm(uint64_t a,void*b,size_t s){vm_size_t g=0;return vm_read_overwrite(g_task,(vm_address_t)a,s,(vm_address_t)b,&g)==0&&g==s;}
static uint64_t r64(uint64_t a){uint64_t v=0;rm(a,&v,8);return v;}
static float rf(uint64_t a){float v=0;rm(a,&v,4);return v;}
static bool vptr(uint64_t p){return p>0x100000ULL&&p<0x800000000000ULL;}
static bool is_sid(uint64_t v){return v>=76561197900000000ULL&&v<76561300000000000ULL;}
static pid_t fr(){pid_t pids[4096];int n=proc_listpids(PROC_ALL_PIDS,0,pids,sizeof(pids));for(int i=0;i<n/(int)sizeof(pid_t);i++){char p[1024];if(proc_pidpath(pids[i],p,sizeof(p))>0&&strstr(p,"RustClient"))return pids[i];}return -1;}

int main(){
    printf("=== Entity List Analysis ===\n");
    pid_t pid=fr();if(pid<0){printf("[!] No Rust\n");return 1;}
    if(task_for_pid(mach_task_self(),pid,&g_task)!=0){printf("[!] t_f_p\n");return 1;}

    // Find the list start by looking for the first SteamID in the cluster
    struct Rg{uint64_t s,e;};
    static Rg regs[128000];int rc=0;
    vm_address_t a=0;vm_size_t sz;vm_region_basic_info_data_64_t info;mach_msg_type_number_t cnt;mach_port_t obj;
    while(rc<128000){cnt=VM_REGION_BASIC_INFO_COUNT_64;if(vm_region_64(g_task,&a,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&cnt,&obj))break;
        if((info.protection&1)&&(info.protection&2)&&sz<=64*1024*1024)regs[rc++]={(uint64_t)a,(uint64_t)a+sz};a+=sz;}

    static uint8_t buf[8*1024*1024];
    std::vector<uint64_t> sid_addrs;
    for(int ri=0;ri<rc&&sid_addrs.size()<100;ri++){
        for(uint64_t off=0;off<regs[ri].e-regs[ri].s;off+=8*1024*1024){
            uint64_t ch=regs[ri].e-regs[ri].s-off;if(ch>8*1024*1024)ch=8*1024*1024;
            vm_size_t got=0;
            if(vm_read_overwrite(g_task,(vm_address_t)(regs[ri].s+off),ch,(vm_address_t)buf,&got))break;
            for(size_t i=0;i+8<=got;i+=8){
                uint64_t v;memcpy(&v,buf+i,8);
                if(is_sid(v))sid_addrs.push_back(regs[ri].s+off+i);
            }
        }
    }
    printf("[+] %zu SteamIDs found\n",sid_addrs.size());

    // Sort by address to see the list structure
    std::sort(sid_addrs.begin(),sid_addrs.end());

    // Analyze first 20 entries
    printf("\n=== Entity list entries (first 20) ===\n");
    printf("%-18s %-16s %-18s %-18s\n","Addr","SID","Ptr at -0x8","Ptr at +0x8");
    for(size_t i=0;i<std::min(sid_addrs.size(),(size_t)20);i++){
        uint64_t addr=sid_addrs[i];
        uint64_t sid=r64(addr);
        uint64_t before=r64(addr-8);
        uint64_t after=r64(addr+8);
        printf("0x%-16llx %-16llu 0x%-16llx 0x%-16llx\n",
               addr,sid%100000,before,after);
    }

    // Check if entries are exactly 0x10 apart
    printf("\n=== Spacing check ===\n");
    if(sid_addrs.size()>=2){
        for(size_t i=1;i<std::min(sid_addrs.size(),(size_t)10);i++){
            printf("  %zu -> %zu: 0x%llx (0x%llx)\n",i-1,i,sid_addrs[i]-sid_addrs[i-1],sid_addrs[i]-sid_addrs[i-1]);
        }
    }

    // Now assume structure is: {ptr, sid} or {sid, ptr}
    // If spacing is 0x10, then each entry is 16 bytes
    // Try: entry = {entity_ptr, steamID}
    printf("\n=== Testing: entity_ptr at sid_addr - 0x8 ===\n");
    for(size_t i=0;i<std::min(sid_addrs.size(),(size_t)10);i++){
        uint64_t addr=sid_addrs[i];
        uint64_t entity=r64(addr-8);
        uint64_t sid=r64(addr);
        bool entity_ok=vptr(entity);
        printf("  SID=%llu entity=0x%llx %s\n",sid%100000,entity,entity_ok?"VALID":"INVALID");
        
        if(entity_ok){
            // Read entity's first 8 bytes (should be vtable)
            uint64_t vtable=r64(entity);
            printf("    vtable=0x%llx\n",vtable);
            
            // Look for position in entity (try common offsets)
            for(int po=0x100;po<0x800;po+=4){
                float px=rf(entity+po),pz=rf(entity+po+8);
                if(std::isfinite(px)&&std::isfinite(pz)&&px>-5000&&px<5000&&pz>-5000&&pz<5000&&(px!=0||pz!=0)){
                    printf("    POSSIBLE POS at +0x%x: (%.1f,%.1f)\n",po,px,pz);
                }
            }
        }
    }

    return 0;
}