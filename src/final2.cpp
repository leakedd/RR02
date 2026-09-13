// RR02/final2.cpp — Find positions by scanning SteamID regions
// 1. Scan heap for all SteamIDs
// 2. For each, dump ±0x1000 bytes around
// 3. Look for world-coord floats in that window
// 4. Test movement

#include <cstdio>
#include <cstdint>
#include <cmath>
#include <vector>
#include <algorithm>
#include <unistd.h>
#include <mach/mach.h>
#include <libproc.h>

static task_t g_task;
static bool rm(uint64_t a,void*b,size_t s){vm_size_t g=0;return vm_read_overwrite(g_task,(vm_address_t)a,s,(vm_address_t)b,&g)==0&&g==s;}
static uint64_t r64(uint64_t a){uint64_t v=0;rm(a,&v,8);return v;}
static float rf(uint64_t a){float v=0;rm(a,&v,4);return v;}
static bool vptr(uint64_t p){return p>0x100000ULL&&p<0x800000000000ULL;}
static bool is_sid(uint64_t v){return v>=76561197900000000ULL&&v<76561300000000000ULL;}
static bool is_world(float x,float y,float z){return std::isfinite(x)&&std::isfinite(z)&&x>-4100&&x<4100&&z>-4100&&z<4100&&y>-500&&y<3000;}
static pid_t fr(){pid_t pids[4096];int n=proc_listpids(PROC_ALL_PIDS,0,pids,sizeof(pids));for(int i=0;i<n/(int)sizeof(pid_t);i++){char p[1024];if(proc_pidpath(pids[i],p,sizeof(p))>0&&strstr(p,"RustClient"))return pids[i];}return -1;}

struct Player{uint64_t sid;uint64_t sid_addr;float x,y,z;int pos_off;};

int main(){
    printf("=== Final2: SteamID-based scan ===\n");
    pid_t pid=fr();if(pid<0){printf("[!] No Rust\n");return 1;}
    if(task_for_pid(mach_task_self(),pid,&g_task)!=0){printf("[!] t_f_p\n");return 1;}

    struct Rg{uint64_t s,e;};
    static Rg regs[128000];int rc=0;
    vm_address_t a=0;vm_size_t sz;vm_region_basic_info_data_64_t info;mach_msg_type_number_t cnt;mach_port_t obj;
    while(rc<128000){cnt=VM_REGION_BASIC_INFO_COUNT_64;if(vm_region_64(g_task,&a,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&cnt,&obj))break;
        if((info.protection&1)&&(info.protection&2)&&sz<=64*1024*1024)regs[rc++]={(uint64_t)a,(uint64_t)a+sz};a+=sz;}

    static uint8_t buf[8*1024*1024];
    std::vector<uint64_t> sid_addrs;

    // Phase 1: find all SteamIDs
    printf("[*] Scanning for SteamIDs...\n");
    for(int ri=0;ri<rc&&sid_addrs.size()<1000;ri++){
        for(uint64_t off=0;off<regs[ri].e-regs[ri].s;off+=8*1024*1024){
            uint64_t ch=regs[ri].e-regs[ri].s-off;if(ch>8*1024*1024)ch=8*1024*1024;
            vm_size_t got=0;
            if(vm_read_overwrite(g_task,(vm_address_t)(regs[ri].s+off),ch,(vm_address_t)buf,&got))break;
            for(size_t i=0;i+8<=got;i+=8){
                uint64_t v;memcpy(&v,buf+i,8);
                if(is_sid(v)) sid_addrs.push_back(regs[ri].s+off+i);
            }
        }
    }
    printf("[+] %zu SteamIDs\n",sid_addrs.size());

    // Phase 2: for each SteamID, look for world positions within ±0x1000
    printf("[*] Scanning for positions near SteamIDs...\n");
    std::vector<Player> players;
    for(auto addr:sid_addrs){
        uint64_t sid=r64(addr);
        // Scan window
        for(int off=-0x1000;off<=0x1000;off+=4){
            float x,y,z;
            rm(addr+off,&x,4);rm(addr+off+4,&y,4);rm(addr+off+8,&z,4);
            if(is_world(x,y,z)&&(x!=0||z!=0)){
                // Check if this looks like a position (not random garbage)
                // Real positions are usually not exactly 0,0,0 and are finite
                Player p;
                p.sid=sid;p.sid_addr=addr;p.x=x;p.y=y;p.z=z;p.pos_off=off;
                players.push_back(p);
            }
        }
    }
    printf("[+] %zu potential player positions\n",players.size());

    // Dedup by SID (keep first)
    std::vector<Player> uniq;
    for(auto& p:players){
        bool dup=false;
        for(auto& u:uniq)if(u.sid==p.sid){dup=true;break;}
        if(!dup)uniq.push_back(p);
    }
    printf("[+] %zu unique players\n",uniq.size());

    // Show sample
    printf("\n=== Sample positions ===\n");
    for(size_t i=0;i<std::min(uniq.size(),(size_t)20);i++){
        auto& p=uniq[i];
        printf("SID=%llu @0x%llx pos=(%.1f,%.1f,%.1f) off=%+d\n",
               p.sid%100000,p.sid_addr,p.x,p.y,p.z,p.pos_off);
    }

    // Phase 3: movement test
    if(!uniq.empty()){
        printf("\n=== Movement test (3s) ===\n");
        printf("BOUGE TOI EN JEU !\n");
        fflush(stdout);
        
        // Snapshot 1
        struct Snap{uint64_t sid;float x,z;};
        std::vector<Snap> s1;
        for(auto& p:uniq)s1.push_back({p.sid,p.x,p.z});
        sleep(3);
        
        // Snapshot 2 + compare
        int moved=0;
        for(size_t i=0;i<uniq.size();i++){
            float nx=rf(uniq[i].sid_addr+uniq[i].pos_off);
            float nz=rf(uniq[i].sid_addr+uniq[i].pos_off+8);
            float dx=nx-s1[i].x,dz=nz-s1[i].z,dist=sqrtf(dx*dx+dz*dz);
            if(dist>0.5f){
                printf("  MOVED SID=%llu: (%.1f,%.1f)->(%.1f,%.1f) %.1fm\n",
                       s1[i].sid%100000,s1[i].x,s1[i].z,nx,nz,dist);
                moved++;
            }
        }
        printf("  %d/%zu moved\n",moved,uniq.size());
    }

    return 0;
}