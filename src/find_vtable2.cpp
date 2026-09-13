// RR02/find_vtable2.cpp — Find vtable by scanning for pointers TO klass
// Then scan for objects with that vtable
#include <cstdio>
#include <cstdint>
#include <cmath>
#include <cstring>
#include <vector>
#include <algorithm>
#include <unistd.h>
#include <mach/mach.h>
#include <libproc.h>

static task_t g_task;
static bool read_mem(uint64_t a,void*b,size_t s) { vm_size_t g=0; return vm_read_overwrite(g_task,(vm_address_t)a,s,(vm_address_t)b,&g)==0&&g==s; }
static uint64_t r64(uint64_t a) { uint64_t v=0; read_mem(a,&v,8); return v; }
static float rf(uint64_t a) { float v=0; read_mem(a,&v,4); return v; }
static bool vptr(uint64_t p) { return p>0x100000ULL&&p<0x800000000000ULL; }
static bool is_sid(uint64_t v) { return v>=76561197900000000ULL&&v<76561300000000000ULL; }
static pid_t fr() { pid_t pids[4096]; int n=proc_listpids(PROC_ALL_PIDS,0,pids,sizeof(pids));
    for(int i=0;i<n/(int)sizeof(pid_t);i++){char p[1024];if(proc_pidpath(pids[i],p,sizeof(p))>0&&strstr(p,"RustClient"))return pids[i];} return -1; }

int main() {
    printf("=== Find vtable for BasePlayer ===\n");
    pid_t pid=fr(); if(pid<0){printf("[!] No Rust\n");return 1;}
    if(task_for_pid(mach_task_self(),pid,&g_task)!=0){printf("[!] t_f_p\n");return 1;}

    uint64_t KLASS=0x105c66640;
    
    struct Rg { uint64_t s,e; };
    static Rg regs[128000]; int rc=0;
    vm_address_t a=0; vm_size_t sz; vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt; mach_port_t obj;
    while(rc<128000){cnt=VM_REGION_BASIC_INFO_COUNT_64;if(vm_region_64(g_task,&a,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&cnt,&obj))break;
        if((info.protection&1)&&sz<=256*1024*1024)regs[rc++]={(uint64_t)a,(uint64_t)a+sz}; a+=sz;}

    static uint8_t buf[8*1024*1024];
    
    // STEP 1: Find all vtables (addresses whose first 8 bytes == KLASS)
    std::vector<uint64_t> vtables;
    printf("[*] Phase 1: scanning for vtables...\n");
    for(int ri=0;ri<rc&&vtables.size()<1000;ri++){
        for(uint64_t off=0;off<regs[ri].e-regs[ri].s;off+=8*1024*1024){
            uint64_t ch=regs[ri].e-regs[ri].s-off; if(ch>8*1024*1024)ch=8*1024*1024;
            vm_size_t got=0;
            if(vm_read_overwrite(g_task,(vm_address_t)(regs[ri].s+off),ch,(vm_address_t)buf,&got))break;
            for(size_t i=0;i+8<=got;i+=8){
                uint64_t v; memcpy(&v,buf+i,8);
                if(v==KLASS) vtables.push_back(regs[ri].s+off+i);
            }
        }
    }
    printf("[+] %zu potential vtables found\n", vtables.size());
    
    // STEP 2: For each vtable candidate, scan heap for objects pointing to it
    // But first, filter vtables by checking that they have reasonable content
    // (a vtable should be at least 16 bytes, readable, with valid pointers)
    std::vector<uint64_t> good_vtables;
    for(auto vt:vtables){
        // Check vtable has at least a few valid method pointers
        int valid_methods=0;
        for(int j=0;j<5;j++){
            uint64_t mp=r64(vt+8+j*8);
            if(vptr(mp)&&mp>0x1000ULL) valid_methods++;
        }
        if(valid_methods>=2) good_vtables.push_back(vt);
    }
    printf("[+] %zu good vtables (>=2 valid method ptrs)\n", good_vtables.size());
    
    // STEP 3: For each good vtable, scan for objects
    // Show top vtables by object count
    printf("\n=== Scanning for objects ===\n");
    struct VtableScore { uint64_t vt; int count; uint64_t sample_obj; uint64_t sample_sid; };
    std::vector<VtableScore> scores;
    
    for(auto vt:good_vtables){
        int obj_count=0;
        uint64_t sample_obj=0, sample_sid=0;
        
        for(int ri=0;ri<rc&&obj_count<5000;ri++){
            if(!(regs[ri].e-regs[ri].s)) continue;
            for(uint64_t off=0;off<regs[ri].e-regs[ri].s;off+=8*1024*1024){
                uint64_t ch=regs[ri].e-regs[ri].s-off; if(ch>8*1024*1024)ch=8*1024*1024;
                vm_size_t got=0;
                if(vm_read_overwrite(g_task,(vm_address_t)(regs[ri].s+off),ch,(vm_address_t)buf,&got))break;
                for(size_t i=0;i+8<=got;i+=8){
                    uint64_t v; memcpy(&v,buf+i,8);
                    if(v!=vt) continue;
                    obj_count++;
                    if(!sample_obj){
                        sample_obj=regs[ri].s+off+i;
                        sample_sid=r64(sample_obj+0x700);
                    }
                }
            }
        }
        
        if(obj_count>=1){
            scores.push_back({vt,obj_count,sample_obj,sample_sid});
        }
    }
    
    // Sort by count desc
    std::sort(scores.begin(),scores.end(),[](auto&a,auto&b){return a.count>b.count;});
    
    printf("\n=== Top vtables ===\n");
    for(size_t i=0;i<std::min(scores.size(),(size_t)15);i++){
        auto& s=scores[i];
        printf("  vtable=0x%llx obj_count=%d sample=[0x%llx sid=%llu]\n",
               s.vt, s.count, s.sample_obj, s.sample_sid%100000);
    }
    
    // STEP 4: For the best vtable, test dump offsets
    if(!scores.empty()){
        auto best=scores[0];
        uint64_t VT=best.vt;
        printf("\n=== Testing with vtable 0x%llx ===\n", VT);
        
        // Find all objects with this vtable again, now filtering by SID
        std::vector<uint64_t> objects;
        for(int ri=0;ri<rc&&objects.size()<200;ri++){
            if(!(regs[ri].e-regs[ri].s)) continue;
            for(uint64_t off=0;off<regs[ri].e-regs[ri].s;off+=8*1024*1024){
                uint64_t ch=regs[ri].e-regs[ri].s-off; if(ch>8*1024*1024)ch=8*1024*1024;
                vm_size_t got=0;
                if(vm_read_overwrite(g_task,(vm_address_t)(regs[ri].s+off),ch,(vm_address_t)buf,&got))break;
                for(size_t i=0;i+8<=got;i+=8){
                    uint64_t v; memcpy(&v,buf+i,8);
                    if(v!=VT) continue;
                    uint64_t obj=regs[ri].s+off+i;
                    uint64_t sid=r64(obj+0x700);
                    if(is_sid(sid)) objects.push_back(obj);
                }
            }
        }
        
        printf("[+] %zu objects with valid SID\n", objects.size());
        
        // Test PM & position
        int pm_ok=0, pos_ok=0, nz=0;
        for(auto obj:objects){
            uint64_t pm=r64(obj+0x6F0);
            if(!vptr(pm)) continue;
            pm_ok++;
            float px=rf(pm+0x2F8),pz=rf(pm+0x2F8+8);
            if(!std::isfinite(px)||!std::isfinite(pz)) continue;
            if(px<-5000||px>5000||pz<-5000||pz>5000) continue;
            pos_ok++;
            if(px!=0||pz!=0) nz++;
        }
        printf("  PM valid: %d/%zu\n", pm_ok, objects.size());
        printf("  Pos valid: %d/%zu\n", pos_ok, objects.size());
        printf("  Non-zero pos: %d\n", nz);
        
        // Show first 10
        printf("\n  Sample positions:\n");
        int shown=0;
        for(auto obj:objects){
            if(shown>=10) break;
            uint64_t pm=r64(obj+0x6F0);
            if(!vptr(pm)) continue;
            float px=rf(pm+0x2F8),py=rf(pm+0x2F8+4),pz=rf(pm+0x2F8+8);
            uint64_t sid=r64(obj+0x700);
            printf("    SID=%llu pos=(%.1f,%.1f,%.1f)\n", sid%100000, px,py,pz);
            shown++;
        }
    }
    
    return 0;
}