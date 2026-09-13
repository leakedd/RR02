// RR02/final.cpp — Combine find_class klass + dump offsets
// Klass=0x105c66640, BP_userID=+0x700, BP_PM=+0x6F0, PM_pos=+0x2F8, BP_name=+0x2D8
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

static bool is_sid(uint64_t v) { return v>=76561197900000000ULL && v<76561300000000000ULL; }

static pid_t find_rust() {
    pid_t pids[4096]; int n=proc_listpids(PROC_ALL_PIDS,0,pids,sizeof(pids));
    for(int i=0;i<n/(int)sizeof(pid_t);i++){
        char p[1024]; if(proc_pidpath(pids[i],p,sizeof(p))>0&&strstr(p,"RustClient")) return pids[i];
    }
    return -1;
}

struct Player { uint64_t bp, sid, pm; float x,y,z; };

int main() {
    printf("=== RR02 Final Test ===\n");
    pid_t pid=find_rust();
    if(pid<0){printf("[!] No Rust\n");return 1;}
    if(task_for_pid(mach_task_self(),pid,&g_task)!=0){printf("[!] t_f_p\n");return 1;}

    // Use klass from find_class
    uint64_t KLASS = 0x105c66640;
    
    // Verify klass has "BasePlayer" name
    uint64_t np=r64(KLASS+0x10);
    char nb[64]={0};
    read_mem(np,nb,32);
    printf("[+] Klass name: %s\n",nb);

    // Scan heap for objects with this klass
    struct Rg { uint64_t s,e; };
    static Rg regs[128000]; int rc=0;
    vm_address_t a=0; vm_size_t sz; vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt; mach_port_t obj;
    while(rc<128000){
        cnt=VM_REGION_BASIC_INFO_COUNT_64;
        if(vm_region_64(g_task,&a,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&cnt,&obj))break;
        if((info.protection&VM_PROT_READ)&&(info.protection&VM_PROT_WRITE)&&sz<=256*1024*1024) regs[rc++]={(uint64_t)a,(uint64_t)a+sz};
        a+=sz;
    }

    static uint8_t buf[8*1024*1024];
    std::vector<Player> players;

    for(int ri=0;ri<rc&&players.size()<200;ri++){
        for(uint64_t off=0;off<regs[ri].e-regs[ri].s;off+=8*1024*1024){
            uint64_t ch=regs[ri].e-regs[ri].s-off; if(ch>8*1024*1024)ch=8*1024*1024;
            vm_size_t got=0;
            if(vm_read_overwrite(g_task,(vm_address_t)(regs[ri].s+off),ch,(vm_address_t)buf,&got))break;
            size_t n=got/8;
            for(size_t i=0;i<n;i++){
                uint64_t v; memcpy(&v,buf+i*8,8);
                if(v!=KLASS) continue;
                uint64_t bp=regs[ri].s+off+i*8;
                
                uint64_t sid=r64(bp+0x700);
                if(!is_sid(sid)) continue;
                
                uint64_t pm=r64(bp+0x6F0);
                if(!vptr(pm)) continue;
                
                float px=rf(pm+0x2F8),pz=rf(pm+0x2F8+8);
                if(!std::isfinite(px)||!std::isfinite(pz)) continue;
                if(px<-5000||px>5000||pz<-5000||pz>5000) continue;
                
                // Dedup by SID
                bool dup=false;
                for(auto& p:players) if(p.sid==sid){dup=true;break;}
                if(dup) continue;
                
                Player pl;
                pl.bp=bp; pl.sid=sid; pl.pm=pm;
                pl.x=px; pl.y=rf(pm+0x2F8+4); pl.z=pz;
                players.push_back(pl);
            }
        }
    }

    printf("[+] %zu players\n", players.size());
    
    // Show non-zero positions
    int nz=0;
    for(auto& p:players){
        if(p.x!=0||p.z!=0){
            printf("  SID=%llu pos=(%.1f,%.1f,%.1f)\n", p.sid%100000, p.x, p.y, p.z);
            nz++;
        }
    }
    printf("[+] %d with non-zero pos\n", nz);

    if(players.empty()){printf("[!] No players\n"); return 1;}

    // TEST MOVEMENT: 2 snapshots
    printf("\n*** SNAPSHOT 1 ***\n");
    std::vector<float> s1x, s1y, s1z;
    for(auto& p:players){
        s1x.push_back(rf(p.pm+0x2F8));
        s1y.push_back(rf(p.pm+0x2F8+4));
        s1z.push_back(rf(p.pm+0x2F8+8));
    }
    
    printf("BOUGE TOI EN JEU ! (3 secondes)\n");
    fflush(stdout);
    sleep(3);
    
    printf("*** SNAPSHOT 2 ***\n");
    int moved=0;
    for(size_t i=0;i<players.size();i++){
        float nx=rf(players[i].pm+0x2F8);
        float nz=rf(players[i].pm+0x2F8+8);
        float dx=nx-s1x[i], dz=nz-s1z[i];
        float dist=sqrtf(dx*dx+dz*dz);
        if(dist>0.5f){
            printf("  MOVED %llu: (%.1f,%.1f)->(%.1f,%.1f) %.1fm\n", players[i].sid%100000, s1x[i],s1z[i],nx,nz,dist);
            moved++;
        }
    }
    printf("  %d/%zu moved\n", moved, players.size());
    
    return 0;
}