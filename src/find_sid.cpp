// RR02/find_sid.cpp — Scan 21 objects with vtable=0x105597a30
// For each, find at what offset (0x000-0x800) the SteamID lives
#include <cstdio>
#include <cstdint>
#include <cmath>
#include <vector>
#include <unordered_set>
#include <unistd.h>
#include <mach/mach.h>
#include <libproc.h>

static task_t g_task;
static bool rm(uint64_t a,void*b,size_t s){vm_size_t g=0;return vm_read_overwrite(g_task,(vm_address_t)a,s,(vm_address_t)b,&g)==0&&g==s;}
static uint64_t r64(uint64_t a){uint64_t v=0;rm(a,&v,8);return v;}
static float rf(uint64_t a){float v=0;rm(a,&v,4);return v;}
static bool vptr(uint64_t p){return p>0x100000ULL&&p<0x800000000000ULL;}
static bool is_sid(uint64_t v){return v>=76561197900000000ULL&&v<76561300000000000ULL;}
static pid_t fr(){pid_t pids[4096];int n=proc_listpids(PROC_ALL_PIDS,0,pids,sizeof(pids));
    for(int i=0;i<n/(int)sizeof(pid_t);i++){char p[1024];if(proc_pidpath(pids[i],p,sizeof(p))>0&&strstr(p,"RustClient"))return pids[i];}return -1;}

int main(){
    printf("=== Find SID offset for BasePlayer ===\n");
    pid_t pid=fr();if(pid<0){printf("[!] No Rust\n");return 1;}
    if(task_for_pid(mach_task_self(),pid,&g_task)!=0){printf("[!] t_f_p\n");return 1;}

    uint64_t VT=0x105597a30;

    struct Rg{uint64_t s,e;};
    static Rg regs[128000];int rc=0;
    vm_address_t a=0;vm_size_t sz;vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt;mach_port_t obj;
    while(rc<128000){cnt=VM_REGION_BASIC_INFO_COUNT_64;if(vm_region_64(g_task,&a,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&cnt,&obj))break;
        if((info.protection&1)&&(info.protection&2)&&sz<=64*1024*1024)regs[rc++]={(uint64_t)a,(uint64_t)a+sz};a+=sz;}

    static uint8_t buf[8*1024*1024];
    std::vector<uint64_t> objects;

    for(int ri=0;ri<rc&&objects.size()<100;ri++){
        for(uint64_t off=0;off<regs[ri].e-regs[ri].s;off+=8*1024*1024){
            uint64_t ch=regs[ri].e-regs[ri].s-off;if(ch>8*1024*1024)ch=8*1024*1024;
            vm_size_t got=0;
            if(vm_read_overwrite(g_task,(vm_address_t)(regs[ri].s+off),ch,(vm_address_t)buf,&got))break;
            for(size_t i=0;i+8<=got;i+=8){
                uint64_t v;memcpy(&v,buf+i,8);
                if(v==VT) objects.push_back(regs[ri].s+off+i);
            }
        }
    }
    printf("[+] %zu objects\n", objects.size());

    // For each object, scan offsets 0x000-0x800 for SID
    std::unordered_map<int,int> sid_offsets; // offset -> count
    for(auto obj:objects){
        for(int so=0;so<0x800;so+=8){
            uint64_t sid=r64(obj+so);
            if(is_sid(sid)) sid_offsets[so]++;
        }
    }

    // Show top offsets
    printf("\n=== SteamID offsets found ===\n");
    std::vector<std::pair<int,int>> sorted;
    for(auto& p:sid_offsets) sorted.push_back({p.second,p.first});
    std::sort(sorted.rbegin(),sorted.rend());
    for(auto& p:sorted){
        printf("  +0x%03x: %d objects\n",p.second,p.first);
    }

    // For the most common SID offset, also check what's at +0x6F0 and +0x530 etc
    if(!sorted.empty()){
        int best_off=sorted[0].second;
        printf("\n=== Using best SID offset +0x%x ===\n",best_off);
        
        // Deduplicate by SID
        std::vector<uint64_t> uniq;
        for(auto obj:objects){
            uint64_t sid=r64(obj+best_off);
            if(!is_sid(sid)) continue;
            bool dup=false;
            for(auto u:uniq){if(r64(u+best_off)==sid){dup=true;break;}}
            if(!dup) uniq.push_back(obj);
        }
        printf("%zu unique SIDs\n",uniq.size());

        // Test PM offsets
        printf("\nTesting PM offsets:\n");
        for(int po=0x400;po<0x800;po+=8){
            int pm_ok=0;
            for(auto u:uniq){
                uint64_t pm=r64(u+po);
                if(vptr(pm)) pm_ok++;
            }
            if(pm_ok>=uniq.size()/2){
                printf("  +0x%03x: %d/%zu PM valid\n",po,pm_ok,uniq.size());
                // Also check for position in PM
                for(int ppos=0x100;ppos<0x400;ppos+=4){
                    int pos_ok=0;
                    for(auto u:uniq){
                        uint64_t pm=r64(u+po);
                        if(!vptr(pm)) continue;
                        float px=rf(pm+ppos),pz=rf(pm+ppos+8);
                        if(std::isfinite(px)&&std::isfinite(pz)&&px>-5000&&px<5000&&pz>-5000&&pz<5000&&(px!=0||pz!=0))
                            pos_ok++;
                    }
                    if(pos_ok>=3){
                        printf("    PM+0x%03x: %d non-zero positions\n",ppos,pos_ok);
                        // Show samples
                        for(auto u:uniq){
                            uint64_t pm=r64(u+po);
                            if(!vptr(pm)) continue;
                            float px=rf(pm+ppos),py=rf(pm+ppos+4),pz=rf(pm+ppos+8);
                            if(px!=0||pz!=0)
                                printf("      SID=%llu (%.1f,%.1f,%.1f)\n",r64(u+best_off)%100000,px,py,pz);
                        }
                        // Movement test
                        printf("      Movement test...\n");
                        std::vector<uint64_t> px_pms;
                        for(auto u:uniq){uint64_t pm=r64(u+po);if(vptr(pm))px_pms.push_back(pm);}
                        sleep(2);
                        int moved=0;
                        for(auto pm:px_pms){
                            float nx=rf(pm+ppos),nz=rf(pm+ppos+8);
                            float ox=rf(pm+ppos),oz=rf(pm+ppos+8);
                            float d=sqrtf((nx-ox)*(nx-ox)+(nz-oz)*(nz-oz));
                            if(d>0.5f) moved++;
                        }
                        printf("      %d moved\n",moved);
                        break;
                    }
                }
            }
        }
    }

    return 0;
}
