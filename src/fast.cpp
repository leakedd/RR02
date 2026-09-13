// RR02/fast.cpp — Optimized: find vtable->objects in one pass, then test dump offsets
#include <cstdio>
#include <cstdint>
#include <cmath>
#include <cstring>
#include <vector>
#include <algorithm>
#include <unordered_set>
#include <unistd.h>
#include <mach/mach.h>
#include <libproc.h>

static task_t g_task;
static bool rm(uint64_t a,void*b,size_t s) { vm_size_t g=0; return vm_read_overwrite(g_task,(vm_address_t)a,s,(vm_address_t)b,&g)==0&&g==s; }
static uint64_t r64(uint64_t a) { uint64_t v=0; rm(a,&v,8); return v; }
static float rf(uint64_t a) { float v=0; rm(a,&v,4); return v; }
static bool vptr(uint64_t p) { return p>0x100000ULL&&p<0x800000000000ULL; }
static bool is_sid(uint64_t v) { return v>=76561197900000000ULL&&v<76561300000000000ULL; }
static pid_t fr() { pid_t pids[4096]; int n=proc_listpids(PROC_ALL_PIDS,0,pids,sizeof(pids));
    for(int i=0;i<n/(int)sizeof(pid_t);i++){char p[1024];if(proc_pidpath(pids[i],p,sizeof(p))>0&&strstr(p,"RustClient"))return pids[i];} return -1; }

int main() {
    printf("=== Fast scan ===\n");
    pid_t pid=fr(); if(pid<0){printf("[!] No Rust\n");return 1;}
    if(task_for_pid(mach_task_self(),pid,&g_task)!=0){printf("[!] t_f_p\n");return 1;}

    uint64_t KLASS=0x105c66640;

    // Get regions (limit to < 64MB, read+write)
    struct Rg { uint64_t s,e; };
    static Rg regs[128000]; int rc=0;
    vm_address_t a=0; vm_size_t sz; vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt; mach_port_t obj;
    while(rc<128000){cnt=VM_REGION_BASIC_INFO_COUNT_64;if(vm_region_64(g_task,&a,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&cnt,&obj))break;
        if((info.protection&1)&&(info.protection&2)&&sz<=64*1024*1024)regs[rc++]={(uint64_t)a,(uint64_t)a+sz};a+=sz;}

    static uint8_t buf[8*1024*1024];

    // Phase 1: Find vtables (addr where first 8 bytes == KLASS)
    std::unordered_set<uint64_t> vt_set;
    printf("[*] Phase 1: finding vtables...\n");
    for(int ri=0;ri<rc&&vt_set.size()<100;ri++){
        for(uint64_t off=0;off<regs[ri].e-regs[ri].s;off+=8*1024*1024){
            uint64_t ch=regs[ri].e-regs[ri].s-off; if(ch>8*1024*1024)ch=8*1024*1024;
            vm_size_t got=0;
            if(vm_read_overwrite(g_task,(vm_address_t)(regs[ri].s+off),ch,(vm_address_t)buf,&got))break;
            for(size_t i=0;i+8<=got;i+=8){
                uint64_t v; memcpy(&v,buf+i,8);
                if(v==KLASS) vt_set.insert(regs[ri].s+off+i);
            }
        }
    }
    printf("[+] %zu vtables\n", vt_set.size());
    if(vt_set.empty()){printf("[!] No vtables\n");return 1;}

    // Convert to vector for faster lookup
    std::vector<uint64_t> vt_vec(vt_set.begin(),vt_set.end());
    
    // Phase 2: Find objects matching any vtable
    printf("[*] Phase 2: finding objects...\n");
    struct Obj { uint64_t addr; uint64_t vtable; };
    std::vector<Obj> objects;
    
    for(int ri=0;ri<rc&&objects.size()<5000;ri++){
        for(uint64_t off=0;off<regs[ri].e-regs[ri].s;off+=8*1024*1024){
            uint64_t ch=regs[ri].e-regs[ri].s-off; if(ch>8*1024*1024)ch=8*1024*1024;
            vm_size_t got=0;
            if(vm_read_overwrite(g_task,(vm_address_t)(regs[ri].s+off),ch,(vm_address_t)buf,&got))break;
            for(size_t i=0;i+8<=got;i+=8){
                uint64_t v; memcpy(&v,buf+i,8);
                if(vt_set.count(v)){
                    objects.push_back({regs[ri].s+off+i, v});
                }
            }
        }
    }
    printf("[+] %zu objects total\n", objects.size());
    
    // Phase 3: Group by vtable, test which vtables have valid SID at +0x700
    printf("[*] Phase 3: ranking vtables by SID validity...\n");
    struct VtScore { uint64_t vt; int total; int sid_ok; int pm_ok; float sample_pos[3]; };
    std::unordered_map<uint64_t,VtScore> vtscores;
    
    for(auto& o:objects){
        auto& vs=vtscores[o.vtable];
        vs.vt=o.vtable; vs.total++;
        uint64_t sid=r64(o.addr+0x700);
        if(is_sid(sid)){
            vs.sid_ok++;
            uint64_t pm=r64(o.addr+0x6F0);
            if(vptr(pm)){
                vs.pm_ok++;
                float px=rf(pm+0x2F8),py=rf(pm+0x2F8+4),pz=rf(pm+0x2F8+8);
                if(std::isfinite(px)&&std::isfinite(pz)){vs.sample_pos[0]=px;vs.sample_pos[1]=py;vs.sample_pos[2]=pz;}
            }
        }
    }
    
    // Sort by pm_ok desc
    std::vector<VtScore> ranked;
    for(auto& p:vtscores) ranked.push_back(p.second);
    std::sort(ranked.begin(),ranked.end(),[](auto&a,auto&b){return a.pm_ok>b.pm_ok;});
    
    printf("\n=== Top vtables ===\n");
    printf("%-18s %-8s %-8s %-8s %-24s\n","vtable","total","SID_OK","PM_OK","Sample Pos");
    for(size_t i=0;i<std::min(ranked.size(),(size_t)10);i++){
        auto& r=ranked[i];
        printf("0x%-16llx %-8d %-8d %-8d (%.1f,%.1f,%.1f)\n",
               r.vt,r.total,r.sid_ok,r.pm_ok,r.sample_pos[0],r.sample_pos[1],r.sample_pos[2]);
    }
    
    // Best vtable
    if(!ranked.empty()&&ranked[0].sid_ok>0){
        auto best=ranked[0];
        printf("\n=== Detailed: vtable=0x%llx (%d SID, %d PM) ===\n",best.vt,best.sid_ok,best.pm_ok);
        
        // Collect all objects with this vtable that have SID
        std::vector<uint64_t> bps;
        for(auto& o:objects){
            if(o.vtable!=best.vt) continue;
            uint64_t sid=r64(o.addr+0x700);
            if(is_sid(sid)){
                bool dup=false;
                for(auto b:bps){if(r64(b+0x700)==sid){dup=true;break;}}
                if(!dup) bps.push_back(o.addr);
            }
        }
        printf("  %zu unique players\n", bps.size());
        
        // Show positions
        int shown=0;
        for(auto bp:bps){
            if(shown>=20) break;
            uint64_t pm=r64(bp+0x6F0);
            if(!vptr(pm)) continue;
            float px=rf(pm+0x2F8),py=rf(pm+0x2F8+4),pz=rf(pm+0x2F8+8);
            uint64_t sid=r64(bp+0x700);
            printf("    SID=%llu pos=(%.1f,%.1f,%.1f)\n",sid%100000,px,py,pz);
            shown++;
        }
        
        // Movement test
        if(bps.size()>=1){
            printf("\n  === Movement test (BOUGE TOI!) ===\n");
            struct Snap{uint64_t bp; float x,z;};
            std::vector<Snap> s1;
            for(auto bp:bps){
                uint64_t pm=r64(bp+0x6F0);
                if(!vptr(pm)) continue;
                float px=rf(pm+0x2F8),pz=rf(pm+0x2F8+8);
                if(std::isfinite(px)&&std::isfinite(pz)) s1.push_back({bp,px,pz});
            }
            printf("  Snapshot 1: %zu players. MOVE NOW! (3s)\n",s1.size());
            fflush(stdout);
            sleep(3);
            
            int moved=0;
            for(auto& s:s1){
                uint64_t pm=r64(s.bp+0x6F0);
                if(!vptr(pm)) continue;
                float nx=rf(pm+0x2F8),nz=rf(pm+0x2F8+8);
                float dx=nx-s.x, dz=nz-s.z, dist=sqrtf(dx*dx+dz*dz);
                if(dist>0.5f){moved++;printf("  MOVED: (%.1f,%.1f)->(%.1f,%.1f) %.1fm\n",s.x,s.z,nx,nz,dist);}
            }
            printf("  %d/%zu moved\n",moved,s1.size());
        }
    }
    
    return 0;
}