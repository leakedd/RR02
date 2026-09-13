// RR02/delta.cpp — Delta scan: find position in PM by comparing before/after movement
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
static pid_t fr(){pid_t pids[4096];int n=proc_listpids(PROC_ALL_PIDS,0,pids,sizeof(pids));
    for(int i=0;i<n/(int)sizeof(pid_t);i++){char p[1024];if(proc_pidpath(pids[i],p,sizeof(p))>0&&strstr(p,"RustClient"))return pids[i];}return -1;}

int main(){
    printf("=== Delta Scan ===\n");
    pid_t pid=fr();if(pid<0){printf("[!] No Rust\n");return 1;}
    if(task_for_pid(mach_task_self(),pid,&g_task)!=0){printf("[!] t_f_p\n");return 1;}

    uint64_t VT=0x1279db300;
    int SID_OFF=0x630, PM_OFF=0x530;

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
                uint64_t pm=r64(bp+PM_OFF);
                if(!vptr(pm))continue;
                bool dup=false;
                for(auto b:bps){if(r64(b+SID_OFF)==sid){dup=true;break;}}
                if(!dup)bps.push_back(bp);
            }
        }
    }
    printf("[+] %zu players\n",bps.size());
    if(bps.empty()){printf("[!] No players\n");return 1;}

    // Read full PM (0x400 bytes) for each player - snapshot 1
    const int PM_SIZE=0x400;
    std::vector<std::vector<uint8_t>> snap1;
    for(auto bp:bps){
        uint64_t pm=r64(bp+PM_OFF);
        std::vector<uint8_t> d(PM_SIZE);
        if(!rm(pm,d.data(),PM_SIZE))memset(d.data(),0,PM_SIZE);
        snap1.push_back(d);
    }

    printf("[*] Snapshot 1 done. BOUGE TOI EN JEU ! (4 secondes)\n");
    fflush(stdout);
    sleep(4);

    // Snapshot 2 + compare
    printf("[*] Snapshot 2...\n");
    
    // Track which float offsets changed per player
    struct Delta{int off;float v1,v2;int player_idx;};
    std::vector<Delta> deltas;
    
    for(size_t pi=0;pi<bps.size();pi++){
        uint64_t pm=r64(bps[pi]+PM_OFF);
        std::vector<uint8_t> d2(PM_SIZE);
        if(!rm(pm,d2.data(),PM_SIZE))continue;
        
        for(int bo=0;bo<PM_SIZE;bo+=4){
            float f1,f2;
            memcpy(&f1,&snap1[pi][bo],4);
            memcpy(&f2,&d2[bo],4);
            if(f1!=f2 && std::isfinite(f1) && std::isfinite(f2)){
                deltas.push_back({bo,f1,f2,(int)pi});
            }
        }
    }
    
    printf("[+] %zu changed floats\n",deltas.size());
    
    // Group by offset
    std::vector<std::pair<int,int>> off_counts; // {offset, count}
    for(auto& d:deltas){
        bool found=false;
        for(auto& oc:off_counts){if(oc.first==d.off){oc.second++;found=true;break;}}
        if(!found)off_counts.push_back({d.off,1});
    }
    std::sort(off_counts.begin(),off_counts.end(),[](auto&a,auto&b){return a.second>b.second;});
    
    printf("\n=== Top changed offsets (world coord candidates) ===\n");
    for(auto& oc:off_counts){
        if(oc.second<2)break;
        // Check if values look like world coords (-5000 to 5000)
        bool looks_coord=true;
        int coord_count=0;
        for(auto& d:deltas){
            if(d.off==oc.first){
                if(d.v1>-5000&&d.v1<5000&&d.v2>-5000&&d.v2<5000)coord_count++;
                else looks_coord=false;
            }
        }
        printf("  PM+0x%03x: %d changes, %d in coord range%s\n",
               oc.first,oc.second,coord_count,looks_coord?" <-- COORD":"");
    }
    
    // Show per-player movement
    printf("\n=== Per-player movement (>1m) ===\n");
    for(size_t pi=0;pi<bps.size();pi++){
        uint64_t pm=r64(bps[pi]+PM_OFF);
        if(!vptr(pm))continue;
        uint64_t sid=r64(bps[pi]+SID_OFF);
        
        // Check if ANY offset moved significantly
        bool player_moved=false;
        for(auto& d:deltas){
            if(d.player_idx==(int)pi){
                float diff=fabsf(d.v2-d.v1);
                if(diff>1.0f){
                    if(!player_moved)printf("  SID=%llu:\n",sid%100000);
                    printf("    PM+0x%03x: %.2f -> %.2f (d=%.2f)\n",d.off,d.v1,d.v2,diff);
                    player_moved=true;
                }
            }
        }
    }
    
    return 0;
}