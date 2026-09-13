// RR02/brute.cpp — Brute force: scan ALL heap for moving Vec3 positions
// Strategy: find all float triplets in world coord range, track which move
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
static float rf(uint64_t a){float v=0;rm(a,&v,4);return v;}
static pid_t fr(){pid_t pids[4096];int n=proc_listpids(PROC_ALL_PIDS,0,pids,sizeof(pids));
    for(int i=0;i<n/(int)sizeof(pid_t);i++){char p[1024];if(proc_pidpath(pids[i],p,sizeof(p))>0&&strstr(p,"RustClient"))return pids[i];}return -1;}

static bool is_world(float x,float y,float z){return std::isfinite(x)&&std::isfinite(z)&&x>-4100&&x<4100&&z>-4100&&z<4100&&y>-500&&y<3000;}

int main(){
    printf("=== Brute Force Position Scanner ===\n");
    pid_t pid=fr();if(pid<0){printf("[!] No Rust\n");return 1;}
    if(task_for_pid(mach_task_self(),pid,&g_task)!=0){printf("[!] t_f_p\n");return 1;}

    struct Rg{uint64_t s,e;};
    static Rg regs[128000];int rc=0;
    vm_address_t a=0;vm_size_t sz;vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt;mach_port_t obj;
    while(rc<128000){cnt=VM_REGION_BASIC_INFO_COUNT_64;if(vm_region_64(g_task,&a,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&cnt,&obj))break;
        if((info.protection&1)&&(info.protection&2)&&sz<=64*1024*1024)regs[rc++]={(uint64_t)a,(uint64_t)a+sz};a+=sz;}

    static uint8_t buf[8*1024*1024];

    // Phase 1: find all world-coord float triplets
    struct Pos{uint64_t addr;float x,y,z;};
    std::vector<Pos> positions;

    printf("[*] Scanning for world-coord positions...\n");
    for(int ri=0;ri<rc&&positions.size()<50000;ri++){
        for(uint64_t off=0;off<regs[ri].e-regs[ri].s;off+=8*1024*1024){
            uint64_t ch=regs[ri].e-regs[ri].s-off;if(ch>8*1024*1024)ch=8*1024*1024;
            vm_size_t got=0;
            if(vm_read_overwrite(g_task,(vm_address_t)(regs[ri].s+off),ch,(vm_address_t)buf,&got))break;
            for(size_t i=0;i+12<=got;i+=4){
                float x,y,z;
                memcpy(&x,buf+i,4);
                memcpy(&y,buf+i+4,4);
                memcpy(&z,buf+i+8,4);
                if(is_world(x,y,z)&&(x!=0||z!=0)){
                    positions.push_back({regs[ri].s+off+i,x,y,z});
                    if(positions.size()>=50000)break;
                }
            }
        }
    }
    printf("[+] %zu world-coord positions found\n",positions.size());

    // Phase 2: take snapshot, ask user to move, take second snapshot
    printf("[*] Snapshot 1 recorded. BOUGE TOI EN JEU ! (4 secondes)\n");
    fflush(stdout);

    // Read current values
    std::vector<Pos> snap1=positions;

    sleep(4);

    // Read new values
    std::vector<Pos> snap2;
    printf("[*] Reading snapshot 2...\n");
    for(auto& p:positions){
        float nx=rf(p.addr),ny=rf(p.addr+4),nz=rf(p.addr+8);
        snap2.push_back({p.addr,nx,ny,nz});
    }

    // Phase 3: find moved positions
    printf("[*] Finding moved positions...\n");
    struct Move{uint64_t addr;float dx,dz,dist;float ox,oz,nx,nz;};
    std::vector<Move> moves;
    for(size_t i=0;i<positions.size();i++){
        float dx=snap2[i].x-snap1[i].x;
        float dz=snap2[i].z-snap1[i].z;
        float dist=sqrtf(dx*dx+dz*dz);
        if(dist>2.0f&&is_world(snap2[i].x,snap2[i].y,snap2[i].z)){
            moves.push_back({positions[i].addr,dx,dz,dist,snap1[i].x,snap1[i].z,snap2[i].x,snap2[i].z});
        }
    }

    printf("[+] %zu positions moved >2m\n",moves.size());

    // Sort by distance
    std::sort(moves.begin(),moves.end(),[](auto&a,auto&b){return a.dist>b.dist;});

    // Show top 30
    printf("\n=== Top 30 moved positions ===\n");
    printf("%-18s %-20s %-8s\n","Address","From -> To","Dist");
    for(size_t i=0;i<std::min(moves.size(),(size_t)30);i++){
        auto& m=moves[i];
        printf("0x%-16llx (%.1f,%.1f)->(%.1f,%.1f) %.1fm\n",m.addr,m.ox,m.oz,m.nx,m.nz,m.dist);
    }

    // Phase 4: Analyze - what's NEAR these positions?
    // Check if there's a SteamID nearby
    if(!moves.empty()){
        printf("\n=== Context analysis ===\n");
        for(size_t i=0;i<std::min(moves.size(),(size_t)5);i++){
            auto& m=moves[i];
            uint64_t base=m.addr;
            printf("\nAt 0x%llx:\n",base);
            // Look for SteamID in ±0x800
            for(int off=-0x100;off<=0x700;off+=8){
                uint64_t v=0;rm(base+off,&v,8);
                if(v>=76561197900000000ULL&&v<76561300000000000ULL)
                    printf("  SID at +0x%x (%+d): %llu\n",off,off,(unsigned long long)(v%100000));
            }
            // Look for the vtable nearby
            for(int off=-0x100;off<=0x100;off+=8){
                uint64_t v=0;rm(base+off,&v,8);
                if(v>0x100000000ULL&&v<0x200000000ULL)
                    printf("  Ptr at +0x%x (%+d): 0x%llx\n",off,off,(unsigned long long)v);
            }
        }
    }

    return 0;
}