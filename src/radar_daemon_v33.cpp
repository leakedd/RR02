// radar_daemon_v33 — latence de découverte minimale
//   - scan MEMOIRE PARALLELE (NT threads) : 22 Go en ~2,5 s au lieu de 25-90 s
//   - PASSE CHAUDE (regions connues contenant des joueurs : ~0,8 Go) toutes les 0,3 s -> nouveaux joueurs < 1 s
//   - PASSE COMPLETE toutes les 8 s -> filet de securite + rafraichit la liste des regions chaudes
//   - boucle d'ecriture JSON toutes les 0,5 s (positions + flags)
// usage: ./radar_v33 [threads] [periodePasseCompleteSec] [periodeEcritureSec]
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
#include <atomic>
#include <mutex>
#include <thread>
#include <algorithm>

static task_t T; static pid_t PID;
static const char* OUT="/tmp/rr02_radar.json";
static std::mutex MTX;
static std::vector<uint64_t> BP;                 // BasePlayer valides (partage)
static std::atomic<uint64_t> KB{0}, KM{0};
static int NT=8; static double FULL_PERIOD=8.0, WRITE_PERIOD=0.5;

struct Reg{ uint64_t a,sz; };
static std::vector<Reg> RW;                      // toutes les regions RW
static std::vector<Reg> HOT;                     // regions contenant des candidats (rapide)

static bool rd(uint64_t a,void*b,size_t n){ mach_vm_size_t g=0;
    return mach_vm_read_overwrite(T,a,n,(mach_vm_address_t)b,&g)==KERN_SUCCESS && g==n; }
static uint64_t r64(uint64_t a){ uint64_t v=0; rd(a,&v,8); return v; }
static bool str_at(uint64_t a,char*out,size_t n){ if(!rd(a,out,n-1)) return false; out[n-1]=0; if(!out[0]) return false;
    for(int i=0;out[i];i++) if((unsigned char)out[i]<0x20||(unsigned char)out[i]>0x7e) return false; return true; }
static uint64_t now_s(){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); return (uint64_t)ts.tv_sec*1000+ts.tv_nsec/1000000; }

static void ls_regions(){
    RW.clear(); mach_vm_address_t a=0x100000000ULL;
    for(;;){ mach_vm_address_t q=a; mach_vm_size_t sz=0; vm_region_basic_info_data_64_t bi; mach_port_t ob=0;
        mach_msg_type_number_t ci=VM_REGION_BASIC_INFO_COUNT_64;
        if(mach_vm_region(T,&q,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&bi,&ci,&ob)!=KERN_SUCCESS) break;
        if(sz>0&&(bi.protection&VM_PROT_READ)&&(bi.protection&VM_PROT_WRITE)) RW.push_back({q,sz});
        if(q+sz<=a) break; a=q+sz; }
}
// parcours parallele : chaque thread prend des regions via l'index atomique
// body(ri,cur,buf,len) ; finish() appele une fois par thread a la fin
template<typename F,typename G> static void par(const std::vector<Reg>& regs,F body,G finish){
    std::atomic<size_t> idx{0};
    std::vector<std::thread> th;
    int n=std::max(1,std::min<int>(NT,(int)regs.size()));
    for(int t=0;t<n;t++) th.emplace_back([&,t](){
        const size_t CH=8u<<20; std::vector<unsigned char> buf(CH);
        for(;;){ size_t i=idx++; if(i>=regs.size()) break; const Reg& r=regs[i];
            for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
                mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
                body((int)i,c,buf.data(),(size_t)g); } }
        finish(); });
    for(auto&x:th) x.join();
}
static void discover_klasses(){
    std::atomic<uint64_t> fk{0},fm{0};
    par(RW,[&](int,uint64_t cur,unsigned char* buf,size_t got){
        if(fk&&fm) return;
        for(size_t i=0;i+0x88<=got;i+=8){
            uint64_t X=cur+i;
            if(*(uint64_t*)(buf+i+0x78)!=X) continue;
            uint64_t p=*(uint64_t*)(buf+i+0x10); if(!p) continue;
            char nm[128]; if(!str_at(p,nm,sizeof(nm))) continue;
            if(!fk && !strcmp(nm,"BasePlayer")){ fk=X; if(fm) return; }
            else if(!fm && !strcmp(nm,"PlayerModel")){ fm=X; if(fk) return; }
        } }, []{});
    if(fk) KB.store(fk.load()); if(fm) KM.store(fm.load());
}
// collecte des BasePlayer dans un ensemble de regions ; renvoie aussi les regions "chaudes" touchees
static thread_local std::vector<uint64_t> TL_OK;
static thread_local std::vector<int>      TL_RI;
static void collect(const std::vector<Reg>& regs, bool full,
                    std::vector<uint64_t>& out, std::vector<Reg>& hotOut){
    uint64_t kb=KB.load(), km=KM.load(); if(!kb||!km) return;
    std::mutex MM;
    par(regs,[&](int ri,uint64_t cur,unsigned char* buf,size_t got){
        for(size_t i=0;i+8<=got;i+=8){
            if(*(uint64_t*)(buf+i)!=kb) continue;
            uint64_t o=cur+i, m=r64(o+0x328);
            if(full) TL_RI.push_back(ri);                       // region "chaude" = toute region contenant un candidat
            if(!m || r64(m)!=km) continue;
            // validation renforcee : position saine exigee (evite les objets transitoires)
            float v[3]; if(!rd(m+0x2F8,v,12)) continue;
            if(!std::isfinite(v[0])||!std::isfinite(v[1])||!std::isfinite(v[2])) continue;
            if(fabsf(v[0])>6000||fabsf(v[2])>6000||v[1]<=0.5f||v[1]>900.0f) continue;
            if(fabsf(v[0])<1.0f&&fabsf(v[2])<1.0f) continue;
            uint32_t fl=0; if(!rd(o+0x6D8,&fl,4)) continue;
            TL_OK.push_back(o);
        } },
        [&](){ std::lock_guard<std::mutex> g(MM);
            for(uint64_t o:TL_OK) out.push_back(o);
            if(full) for(int ri:TL_RI){ if(ri>=0&&(size_t)ri<regs.size()) hotOut.push_back(regs[ri]); }
            TL_OK.clear(); TL_RI.clear(); });
}
static size_t pass(bool full){
    std::vector<uint64_t> ok; std::vector<Reg> hot;
    collect(full?RW:HOT,full,ok,hot);
    std::sort(ok.begin(),ok.end()); ok.erase(std::unique(ok.begin(),ok.end()),ok.end());
    size_t added=0, total=0, before=0;
    {   std::lock_guard<std::mutex> g(MTX);
        before=BP.size();
        if(full){
            // la passe complete ne remplace plus : elle FUSIONNE (elle peut rater des entites
            // vues par les passes chaudes) puis elague ce qui ne valide plus
            uint64_t km=KM.load();
            for(uint64_t o : ok) BP.push_back(o);
            std::sort(BP.begin(),BP.end()); BP.erase(std::unique(BP.begin(),BP.end()),BP.end());
            std::vector<uint64_t> keep; keep.reserve(BP.size());
            for(uint64_t o : BP){ uint64_t m=r64(o+0x328); if(!m||r64(m)!=km) continue;
                uint32_t fl=0; if(!rd(o+0x6D8,&fl,4)) continue; keep.push_back(o); }
            BP.swap(keep);
        }
        else {                                                // passe chaude : ajout des nouveaux (sans doublon)
            for(uint64_t o : ok) BP.push_back(o);
            std::sort(BP.begin(),BP.end());
            BP.erase(std::unique(BP.begin(),BP.end()),BP.end());
        }
        total=BP.size(); added = total>before ? total-before : 0;
    }
    if(full){
        std::sort(hot.begin(),hot.end(),[](const Reg&a,const Reg&b){return a.a<b.a;});
        hot.erase(std::unique(hot.begin(),hot.end(),[](const Reg&a,const Reg&b){return a.a==b.a;}),hot.end());
        if(!hot.empty()) HOT=hot;
    }
    return added;
}
static size_t nbp(){ std::lock_guard<std::mutex> g(MTX); return BP.size(); }
static size_t nhot(){ return HOT.size(); }
static void refresher(){
    ls_regions(); discover_klasses();
    uint64_t t0=now_s(); pass(true);
    uint64_t last=now_s();
    printf("[v33] klasses BP=0x%llx PM=0x%llx | regions RW=%zu | passe complete (%.1f s) -> %zu BP, %zu regions chaudes\n",
        (unsigned long long)KB.load(),(unsigned long long)KM.load(),RW.size(),(last-t0)/1000.0,nbp(),nhot());
    fflush(stdout);
    for(;;){
        if((now_s()-last)/1000.0 >= FULL_PERIOD){ uint64_t s=now_s(); pass(true); last=now_s();
            printf("[v33] passe complete %.1f s -> %zu BP, %zu regions chaudes\n",(last-s)/1000.0,nbp(),nhot()); fflush(stdout); }
        else { uint64_t s=now_s(); size_t add=pass(false); uint64_t e=now_s();
            if(add) printf("[v33] +%zu nouveau(x) detecte(s) en %llu ms -> %zu BP\n",add,(unsigned long long)(e-s),nbp()), fflush(stdout);
            else if(e-s>800) printf("[v33] passe chaude lente: %llu ms (%zu BP, %zu regions)\n",(unsigned long long)(e-s),nbp(),nhot()), fflush(stdout); }
        usleep(150000);
    }
}
int main(int argc,char**argv){
    if(argc>1) NT=atoi(argv[1]); if(argc>2) FULL_PERIOD=atof(argv[2]); if(argc>3) WRITE_PERIOD=atof(argv[3]);
    PID=0; { FILE* f=popen("pgrep -x Rust | head -1","r"); char b[64]; if(f&&fgets(b,64,f)) PID=atoi(b); if(f)pclose(f); }
    if(!PID){ printf("Rust absent\n"); return 1; }
    if(task_for_pid(mach_task_self(),PID,&T)!=KERN_SUCCESS){ printf("task_for_pid KO\n"); return 1; }
    printf("[v33] pid=%d threads=%d passeComplete=%.1fs ecriture=%.2fs\n",PID,NT,FULL_PERIOD,WRITE_PERIOD); fflush(stdout);
    std::thread th(refresher); th.detach();

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
        FILE* f=(n?fopen(tmp,"w"):nullptr);
        if(f){
            struct timespec rt; clock_gettime(CLOCK_REALTIME,&rt);
            fprintf(f,"{\"ts\":%.3f,\"count\":%zu,\"on\":%d,\"off\":%d,\"players\":[",
                rt.tv_sec+rt.tv_nsec/1e9,n,onc,(int)n-onc);
            for(size_t i=0;i<n;i++)
                fprintf(f,"%s{\"x\":%.1f,\"y\":%.1f,\"z\":%.1f,\"on\":%d,\"w\":%d,\"id\":%llu}",i?",":"",
                    pos[i*3],pos[i*3+1],pos[i*3+2],on_[i],wd[i],(unsigned long long)ids[i]);
            fprintf(f,"]}"); fclose(f); rename(tmp,OUT);
        }
        usleep((useconds_t)(WRITE_PERIOD*1000000));
    }
}
