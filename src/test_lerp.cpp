// RR02/test_lerp.cpp — Test positionLerp offset (+0x108) + movement test
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
static bool is_sid(uint64_t v){return v>=76561197900000000ULL&&v<76561300000000000ULL;}
static pid_t fr(){pid_t pids[4096];int n=proc_listpids(PROC_ALL_PIDS,0,pids,sizeof(pids));
    for(int i=0;i<n/(int)sizeof(pid_t);i++){char p[1024];if(proc_pidpath(pids[i],p,sizeof(p))>0&&strstr(p,"RustClient"))return pids[i];}return -1;}

int main(){
    printf("=== Test positionLerp +0x108 ===\n");
    pid_t pid=fr();if(pid<0){printf("[!] No Rust\n");return 1;}
    if(task_for_pid(mach_task_self(),pid,&g_task)!=0){printf("[!] t_f_p\n");return 1;}

    uint64_t VT=0x1279db300;
    int SID_OFF=0x630;

    struct Rg{uint64_t s,e;};
    static Rg regs[128000];int rc=0;
    vm_address_t a=0;vm_size_t sz;vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt;mach_port_t obj;
    while(rc<128000){cnt=VM_REGION_BASIC_INFO_COUNT_64;if(vm_region_64(g_task,&a,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&cnt,&obj))break;
        if((info.protection&1)&&(info.protection&2)&&sz<=64*1024*1024)regs[rc++]={(uint64_t)a,(uint64_t)a+sz};a+=sz;}

    static uint8_t buf[8*1024*1024];
    std::vector<uint64_t> bps;

    for(int ri=0;ri<rc&&bps.size()<100;ri++){
        for(uint64_t off=0;off<regs[ri].e-regs[ri].s;off+=8*1024*1024){
            uint64_t ch=regs[ri].e-regs[ri].s-off;if(ch>8*1024*1024)ch=8*1024*1024;
            vm_size_t got=0;
            if(vm_read_overwrite(g_task,(vm_address_t)(regs[ri].s+off),ch,(vm_address_t)buf,&got))break;
            for(size_t i=0;i+8<=got;i+=8){
                uint64_t v;memcpy(&v,buf+i,8);
                if(v!=VT)continue;
                uint64_t bp=regs[ri].s+off+i;
                uint64_t sid=r64(bp+SID_OFF);
                if(!is_sid(sid))continue;
                bool dup=false;
                for(auto b:bps){if(r64(b+SID_OFF)==sid){dup=true;break;}}
                if(!dup)bps.push_back(bp);
            }
        }
    }
    printf("[+] %zu players\n",bps.size());
    if(bps.empty()){printf("[!] No players\n");return 1;}

    // Test positionLerp at +0x108
    printf("\n=== positionLerp (+0x108) non-zero ===\n");
    int nz=0;
    for(auto bp:bps){
        float px=rf(bp+0x108),py=rf(bp+0x10C),pz=rf(bp+0x110);
        if(std::isfinite(px)&&std::isfinite(pz)&&px>-5000&&px<5000&&pz>-5000&&pz<5000&&(px!=0||pz!=0)){
            if(nz<15)printf("  SID=%llu lerp=(%.1f,%.1f,%.1f)\n",r64(bp+SID_OFF)%100000,px,py,pz);
            nz++;
        }
    }
    printf("  %d non-zero\n",nz);

    // Movement test on positionLerp
    printf("\n=== Movement test: positionLerp ===\n");
    struct Snap{uint64_t bp;float x,z;};
    std::vector<Snap> snaps;
    for(auto bp:bps){
        float px=rf(bp+0x108),pz=rf(bp+0x110);
        if(std::isfinite(px)&&std::isfinite(pz))snaps.push_back({bp,px,pz});
    }
    printf("Snapshot 1: %zu. BOUGE TOI EN JEU ! (3s)\n",snaps.size());
    fflush(stdout);
    sleep(3);
    
    int moved=0;
    for(auto& s:snaps){
        float nx=rf(s.bp+0x108),nz=rf(s.bp+0x110);
        float dx=nx-s.x,dz=nz-s.z,dist=sqrtf(dx*dx+dz*dz);
        if(dist>0.5f){moved++;printf("  MOVED %llu: (%.1f,%.1f)->(%.1f,%.1f) %.1fm\n",r64(s.bp+SID_OFF)%100000,s.x,s.z,nx,nz,dist);}
    }
    printf("  %d/%zu moved\n",moved,snaps.size());

    return 0;
}