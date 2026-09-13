// radar_daemon_v31 — v30 + découverte des klasses dans un THREAD séparé (écriture JSON non bloquée)
//   thread  : toutes les 90 s -> klass BasePlayer/PlayerModel + instances validées (+0x328 -> PlayerModel)
//   main    : toutes les 1 s  -> flags(+0x6D8) + position(PlayerModel+0x2F8) -> /tmp/rr02_radar.json
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>
#include <cmath>
#include <ctime>
#include <mutex>
#include <thread>
#include <algorithm>

static task_t T; static pid_t PID;
static const char* OUT="/tmp/rr02_radar.json";
static std::mutex MTX;
static std::vector<uint64_t> BP;      // BasePlayer validés (partagé)
static uint64_t KB=0, KM=0;

static bool rd(uint64_t a,void*b,size_t n){ mach_vm_size_t g=0;
    return mach_vm_read_overwrite(T,a,n,(mach_vm_address_t)b,&g)==KERN_SUCCESS && g==n; }
static uint64_t r64(uint64_t a){ uint64_t v=0; rd(a,&v,8); return v; }
static bool name_of(uint64_t a,char*out,size_t n){ uint64_t p=r64(a); if(!p) return false;
    if(!rd(p,out,n-1)) return false; out[n-1]=0; return true; }
template<typename F> static void scan_rw(F cb){
    mach_vm_address_t a=0x100000000ULL;
    for(;;){
        mach_vm_address_t q=a; mach_vm_size_t sz=0; vm_region_basic_info_data_64_t bi; mach_port_t ob=0;
        mach_msg_type_number_t ci=VM_REGION_BASIC_INFO_COUNT_64;
        if(mach_vm_region(T,&q,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&bi,&ci,&ob)!=KERN_SUCCESS) break;
        if(sz>0 && (bi.protection&VM_PROT_READ) && (bi.protection&VM_PROT_WRITE)){
            const size_t CH=4u<<20; std::vector<unsigned char> buf(CH);
            for(uint64_t cur=q; cur<q+sz; cur+=CH){
                size_t wn=(size_t)std::min<uint64_t>(CH,q+sz-cur); mach_vm_size_t got=0;
                if(mach_vm_read_overwrite(T,cur,wn,(mach_vm_address_t)buf.data(),&got)!=KERN_SUCCESS) continue;
                cb(cur,buf.data(),(size_t)got);
            }
        }
        if(q+sz<=a) break; a=q+sz;
    }
}
static uint64_t find_klass(const char* want){
    uint64_t f=0;
    scan_rw([&](uint64_t cur,unsigned char* buf,size_t got){
        if(f||got<0x100) return;
        for(size_t i=0;i+0x88<=got;i+=8){
            uint64_t X=cur+i;
            if(*(uint64_t*)(buf+i+0x78)!=X) continue;
            char nm[128]; if(!name_of(X+0x10,nm,sizeof(nm))) continue;
            if(!strcmp(nm,want)){ f=X; return; }
        }
    });
    return f;
}
static void discover(){
    uint64_t kb=find_klass("BasePlayer"), km=find_klass("PlayerModel");
    std::vector<uint64_t> cand, ok;
    if(kb&&km){
        scan_rw([&](uint64_t cur,unsigned char* buf,size_t got){
            for(size_t i=0;i+8<=got;i+=8) if(*(uint64_t*)(buf+i)==kb) cand.push_back(cur+i);
        });
        for(uint64_t o : cand){ uint64_t m=r64(o+0x328); if(m&&r64(m)==km) ok.push_back(o); }
    }
    {   std::lock_guard<std::mutex> g(MTX);
        if(!ok.empty()){ KB=kb; KM=km; BP.swap(ok); }      // ne remplace jamais une liste valide par du vide
    }
    printf("[v31] BP=0x%llx PM=0x%llx candidats=%zu valides=%zu\n",
        (unsigned long long)kb,(unsigned long long)km,cand.size(),BP.size()); fflush(stdout);
}
static void worker(){
    for(;;){ discover(); sleep(90); }
}
int main(){
    PID=0; { FILE* f=popen("pgrep -x Rust | head -1","r"); char b[64]; if(f&&fgets(b,64,f)) PID=atoi(b); if(f)pclose(f); }
    if(!PID){ printf("Rust absent\n"); return 1; }
    if(task_for_pid(mach_task_self(),PID,&T)!=KERN_SUCCESS){ printf("task_for_pid KO\n"); return 1; }
    printf("[v31] pid=%d\n",PID); fflush(stdout);
    std::thread th(worker); th.detach();

    for(;;){
        std::vector<uint64_t> bp; { std::lock_guard<std::mutex> g(MTX); bp=BP; }
        std::vector<float> pos; std::vector<int> on_,wd; std::vector<uint64_t> ids;
        for(uint64_t o : bp){
            uint64_t m=r64(o+0x328); if(!m) continue;
            float v[3];
            if(!rd(m+0x2F8,v,12)) continue;
            if(!std::isfinite(v[0])||!std::isfinite(v[1])||!std::isfinite(v[2])) continue;
            if(fabsf(v[0])>6000||fabsf(v[2])>6000) continue;
            if(v[1]<=0.5f||v[1]>900.0f) continue;
            if(fabsf(v[0])<1.0f&&fabsf(v[2])<1.0f) continue;
            uint32_t fl=0; if(!rd(o+0x6D8,&fl,4)) continue;
            pos.push_back(v[0]); pos.push_back(v[1]); pos.push_back(v[2]);
            on_.push_back((fl&0x100)?1:0); wd.push_back((fl&0x40)?1:0);
            ids.push_back(o);
        }
        size_t n=pos.size()/3; int onc=0; for(int x:on_) onc+=x;
        char tmp[256]; snprintf(tmp,sizeof(tmp),"%s.tmp",OUT);
        FILE* f=(n?fopen(tmp,"w"):nullptr);        // liste vide -> on garde le dernier fichier valide
        if(f){
            fprintf(f,"{\"ts\":%ld,\"count\":%zu,\"on\":%d,\"off\":%d,\"players\":[",(long)time(0),n,onc,(int)n-onc);
            for(size_t i=0;i<n;i++)
                fprintf(f,"%s{\"x\":%.1f,\"y\":%.1f,\"z\":%.1f,\"on\":%d,\"w\":%d,\"id\":%llu}",i?",":"",
                    pos[i*3],pos[i*3+1],pos[i*3+2],on_[i],wd[i],(unsigned long long)ids[i]);
            fprintf(f,"]}"); fclose(f); rename(tmp,OUT);
        }
        sleep(1);
    }
}
