// RR02/brute2.cpp — Filtered: only realistic movements (0.5-50m), look for SID nearby
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
static uint64_t r64(uint64_t a){uint64_t v=0;rm(a,&v,8);return v;}
static bool is_world(float x,float y,float z){return std::isfinite(x)&&std::isfinite(z)&&x>-4100&&x<4100&&z>-4100&&z<4100&&y>-500&&y<3000;}
static bool is_sid(uint64_t v){return v>=76561197900000000ULL&&v<76561300000000000ULL;}
static pid_t fr(){pid_t pids[4096];int n=proc_listpids(PROC_ALL_PIDS,0,pids,sizeof(pids));
    for(int i=0;i<n/(int)sizeof(pid_t);i++){char p[1024];if(proc_pidpath(pids[i],p,sizeof(p))>0&&strstr(p,"RustClient"))return pids[i];}return -1;}

int main(){
    printf("=== Brute Force v2 — Realistic movement filter ===\n");
    pid_t pid=fr();if(pid<0){printf("[!] No Rust\n");return 1;}
    if(task_for_pid(mach_task_self(),pid,&g_task)!=0){printf("[!] t_f_p\n");return 1;}

    struct Rg{uint64_t s,e;};
    static Rg regs[128000];int rc=0;
    vm_address_t a=0;vm_size_t sz;vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt;mach_port_t obj;
    while(rc<128000){cnt=VM_REGION_BASIC_INFO_COUNT_64;if(vm_region_64(g_task,&a,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&cnt,&obj))break;
        if((info.protection&1)&&(info.protection&2)&&sz<=64*1024*1024)regs[rc++]={(uint64_t)a,(uint64_t)a+sz};a+=sz;}

    static uint8_t buf[8*1024*1024];

    struct Pos{uint64_t addr;float x,y,z;};
    std::vector<Pos> positions;
    printf("[*] Phase 1: finding world positions...\n");
    for(int ri=0;ri<rc&&positions.size()<100000;ri++){
        for(uint64_t off=0;off<regs[ri].e-regs[ri].s;off+=8*1024*1024){
            uint64_t ch=regs[ri].e-regs[ri].s-off;if(ch>8*1024*1024)ch=8*1024*1024;
            vm_size_t got=0;
            if(vm_read_overwrite(g_task,(vm_address_t)(regs[ri].s+off),ch,(vm_address_t)buf,&got))break;
            for(size_t i=0;i+12<=got;i+=4){
                float x,y,z;
                memcpy(&x,buf+i,4);memcpy(&y,buf+i+4,4);memcpy(&z,buf+i+8,4);
                if(is_world(x,y,z)&&(x!=0||z!=0)){
                    positions.push_back({regs[ri].s+off+i,x,y,z});
                    if(positions.size()>=100000)break;
                }
            }
        }
    }
    printf("[+] %zu positions\n",positions.size());

    // Phase 2: 2 snapshots
    printf("[*] Snapshot 1. BOUGE TOI EN JEU ! (5 secondes)\n");
    fflush(stdout);
    std::vector<float> s1x,s1y,s1z;
    for(auto& p:positions){s1x.push_back(p.x);s1y.push_back(p.y);s1z.push_back(p.z);}
    sleep(5);

    printf("[*] Snapshot 2...\n");
    struct Move{uint64_t addr;float dist,ox,oz,nx,nz;};
    std::vector<Move> moves;
    for(size_t i=0;i<positions.size();i++){
        float nx=rf(positions[i].addr),ny=rf(positions[i].addr+4),nz=rf(positions[i].addr+8);
        float dx=nx-s1x[i],dz=nz-s1z[i],dist=sqrtf(dx*dx+dz*dz);
        // Filter: realistic player movement (0.5m to 50m)
        if(dist>=0.5f&&dist<=50.0f&&is_world(nx,ny,nz)){
            moves.push_back({positions[i].addr,dist,s1x[i],s1z[i],nx,nz});
        }
    }

    printf("[+] %zu realistic moves (0.5-50m)\n",moves.size());
    std::sort(moves.begin(),moves.end(),[](auto&a,auto&b){return a.dist>b.dist;});

    // Show top 50 moves
    printf("\n=== Top 50 realistic moves ===\n");
    for(size_t i=0;i<std::min(moves.size(),(size_t)50);i++){
        auto& m=moves[i];
        // Check for SteamID within ±0x1000
        bool has_sid=false;uint64_t sid=0;int sid_off=0;
        for(int o=-0x1000;o<=0x1000;o+=8){
            uint64_t v=r64(m.addr+o);
            if(is_sid(v)){has_sid=true;sid=v;sid_off=o;break;}
        }
        printf("0x%llx (%.1f,%.1f)->(%.1f,%.1f) %.1fm%s",
               (unsigned long long)m.addr,m.ox,m.oz,m.nx,m.nz,m.dist,
               has_sid?"":"\n");
        if(has_sid)printf(" SID=%llu at %+d\n",(unsigned long long)(sid%100000),sid_off);
    }

    // Summary: how many have SIDs nearby
    int has_sid_count=0;
    for(auto& m:moves){
        for(int o=-0x1000;o<=0x1000;o+=8){
            if(is_sid(r64(m.addr+o))){has_sid_count++;break;}
        }
    }
    printf("\n=== %d/%zu moves have SteamID within ±0x1000 ===\n",has_sid_count,moves.size());

    return 0;
}