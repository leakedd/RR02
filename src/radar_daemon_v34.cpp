// radar_daemon_v34 — v33 (joueurs, latence minimale) + CALQUE ITEMS AU SOL
//   FILTRE FORT d'instance DroppedItem : r64(a+0x210) -> objet de klass "GameObjectRef"
//                                        ET r64(a+0x208) -> objet de klass Item (nom obfusque)
//   POSITION : chemin A -> r64(a+0x90) -> [0] -> +0x90 (Vector3 monde)
//   NOM      : Item -> champ X (klass "ItemDefinition") -> +0x28 (shortname, string managée)
// usage: ./radar_v34 [threads] [periodePasseCompleteSec] [periodeEcritureSec]
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>
#include <map>
#include <string>
#include <cmath>
#include <ctime>
#include <atomic>
#include <mutex>
#include <thread>
#include <algorithm>

static task_t T; static pid_t PID;
static const char* OUT="/tmp/rr02_radar.json";
static const char* DBG="/tmp/rr02_items_dbg.txt";
static std::mutex MTX;
static std::vector<uint64_t> BP;                 // BasePlayer valides (partage)
static std::vector<uint64_t> IT;                 // DroppedItem valides (partage)
static std::map<uint64_t,std::string> NAMES;     // cache noms d'items
static std::atomic<uint64_t> KB{0}, KM{0}, KD{0};
static int NT=8; static double FULL_PERIOD=8.0, WRITE_PERIOD=0.5;
static const char* ITEMCLASS="%842e6b2f32a12d6d9f1a80e7de9e9902d2f3ecdc";

struct Reg{ uint64_t a,sz; };
static std::vector<Reg> RW, HOT;

static bool rd(uint64_t a,void*b,size_t n){ mach_vm_size_t g=0;
    return mach_vm_read_overwrite(T,a,n,(mach_vm_address_t)b,&g)==KERN_SUCCESS && g==n; }
static uint64_t r64(uint64_t a){ uint64_t v=0; rd(a,&v,8); return v; }
static uint32_t r32(uint64_t a){ uint32_t v=0; rd(a,&v,4); return v; }
static bool str_at(uint64_t a,char*out,size_t n){ if(!rd(a,out,n-1)) return false; out[n-1]=0; if(!out[0]) return false;
    for(int i=0;out[i];i++) if((unsigned char)out[i]<0x20||(unsigned char)out[i]>0x7e) return false; return true; }
static std::string kname(uint64_t o){ if(o<0x1000000) return ""; uint64_t k=r64(o); if(k<0x1000000) return "";
    char b[96]={0}; uint64_t np=r64(k+0x10); if(!np||!str_at(np,b,sizeof(b))) return ""; return std::string(b); }
static std::string mstr(uint64_t sp){ if(sp<0x1000000) return ""; int len=(int)r32(sp+0x10);
    if(len<=0||len>120) return ""; uint16_t w[120]; if(!rd(sp+0x14,w,(size_t)len*2)) return "";
    std::string s; for(int i=0;i<len;i++){ if(!w[i]) break; if(w[i]<0x20||w[i]>0x7e) return ""; s.push_back((char)w[i]); }
    return s; }
static bool okname(const std::string&s){ if(s.size()<2||s.size()>48) return false;
    for(char c:s) if(!((c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='.'||c=='_'||c=='-')) return false; return true; }
static uint64_t now_s(){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC,&ts); return (uint64_t)ts.tv_sec*1000+ts.tv_nsec/1000000; }
static bool sane3(const float*v){ return std::isfinite(v[0])&&std::isfinite(v[1])&&std::isfinite(v[2])
    && fabsf(v[0])<6000&&fabsf(v[2])<6000&&v[1]>0.2f&&v[1]<900.0f && !(fabsf(v[0])<1.0f&&fabsf(v[2])<1.0f); }
// position d'une entite non-joueur : chemin A
static bool entpos(uint64_t o,float*out){ uint64_t h=r64(o+0x90); if(h<0x1000000||h>0x300000000000ULL) return false;
    uint64_t d=r64(h+0x00); if(d<0x1000000||d>0x300000000000ULL) return false;
    if(!rd(d+0x90,out,12)) return false; return sane3(out); }

static void ls_regions(){
    RW.clear(); mach_vm_address_t a=0x100000000ULL;
    for(;;){ mach_vm_address_t q=a; mach_vm_size_t sz=0; vm_region_basic_info_data_64_t bi; mach_port_t ob=0;
        mach_msg_type_number_t ci=VM_REGION_BASIC_INFO_COUNT_64;
        if(mach_vm_region(T,&q,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&bi,&ci,&ob)!=KERN_SUCCESS) break;
        if(sz>0&&(bi.protection&VM_PROT_READ)&&(bi.protection&VM_PROT_WRITE)) RW.push_back({q,sz});
        if(q+sz<=a) break; a=q+sz; }
}
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
    std::atomic<uint64_t> fk{0},fm{0},fd{0};
    par(RW,[&](int,uint64_t cur,unsigned char* buf,size_t got){
        if(fk&&fm&&fd) return;
        for(size_t i=0;i+0x88<=got;i+=8){
            uint64_t X=cur+i;
            if(*(uint64_t*)(buf+i+0x78)!=X) continue;
            uint64_t p=*(uint64_t*)(buf+i+0x10); if(!p) continue;
            char nm[128]; if(!str_at(p,nm,sizeof(nm))) continue;
            if(!fk && !strcmp(nm,"BasePlayer")) fk=X;
            else if(!fm && !strcmp(nm,"PlayerModel")) fm=X;
            else if(!fd && !strcmp(nm,"DroppedItem")) fd=X;
        } }, []{});
    if(fk) KB.store(fk.load()); if(fm) KM.store(fm.load()); if(fd) KD.store(fd.load());
}
static thread_local std::vector<uint64_t> TL_OK, TL_IT;
static thread_local std::vector<int>      TL_RI;
static void collect(const std::vector<Reg>& regs, bool full,
                    std::vector<uint64_t>& out, std::vector<uint64_t>& outit, std::vector<Reg>& hotOut){
    uint64_t kb=KB.load(), km=KM.load(), kd=KD.load(); if(!kb||!km) return;
    std::mutex MM;
    par(regs,[&](int ri,uint64_t cur,unsigned char* buf,size_t got){
        for(size_t i=0;i+8<=got;i+=8){
            uint64_t w=*(uint64_t*)(buf+i);
            if(w==kb){
                uint64_t o=cur+i, m=r64(o+0x328);
                if(full) TL_RI.push_back(ri);
                if(!m || r64(m)!=km) continue;
                float v[3]; if(!rd(m+0x2F8,v,12)) continue;
                if(!std::isfinite(v[0])||!std::isfinite(v[1])||!std::isfinite(v[2])) continue;
                if(fabsf(v[0])>6000||fabsf(v[2])>6000||v[1]<=0.5f||v[1]>900.0f) continue;
                if(fabsf(v[0])<1.0f&&fabsf(v[2])<1.0f) continue;
                uint32_t fl=0; if(!rd(o+0x6D8,&fl,4)) continue;
                TL_OK.push_back(o);
            } else if(kd && w==kd){
                uint64_t o=cur+i;
                if(kname(r64(o+0x210))!="GameObjectRef") continue;   // vraie entite, pas un prefab
                uint64_t it=r64(o+0x208); if(kname(it).empty()) continue; // doit avoir un Item
                float v[3]; if(!entpos(o,v)) continue;
                TL_IT.push_back(o);
            }
        } },
        [&](){ std::lock_guard<std::mutex> g(MM);
            for(uint64_t o:TL_OK) out.push_back(o);
            for(uint64_t o:TL_IT) outit.push_back(o);
            if(full) for(int ri:TL_RI){ if(ri>=0&&(size_t)ri<regs.size()) hotOut.push_back(regs[ri]); }
            TL_OK.clear(); TL_IT.clear(); TL_RI.clear(); });
}
static size_t pass(bool full){
    std::vector<uint64_t> ok, oit; std::vector<Reg> hot;
    collect(full?RW:HOT,full,ok,oit,hot);
    std::sort(ok.begin(),ok.end()); ok.erase(std::unique(ok.begin(),ok.end()),ok.end());
    std::sort(oit.begin(),oit.end()); oit.erase(std::unique(oit.begin(),oit.end()),oit.end());
    size_t added=0,total=0,before=0;
    {   std::lock_guard<std::mutex> g(MTX);
        before=BP.size();
        if(full){
            uint64_t km=KM.load();
            for(uint64_t o : ok) BP.push_back(o);
            std::sort(BP.begin(),BP.end()); BP.erase(std::unique(BP.begin(),BP.end()),BP.end());
            std::vector<uint64_t> keep; keep.reserve(BP.size());
            for(uint64_t o : BP){ uint64_t m=r64(o+0x328); if(!m||r64(m)!=km) continue;
                uint32_t fl=0; if(!rd(o+0x6D8,&fl,4)) continue; keep.push_back(o); }
            BP.swap(keep);
        } else {
            for(uint64_t o : ok) BP.push_back(o);
            std::sort(BP.begin(),BP.end());
            BP.erase(std::unique(BP.begin(),BP.end()),BP.end());
        }
        // items : fusion + elagage (position toujours valide exigee)
        std::vector<uint64_t> all=IT;
        for(uint64_t o : oit) all.push_back(o);
        std::sort(all.begin(),all.end()); all.erase(std::unique(all.begin(),all.end()),all.end());
        std::vector<uint64_t> keepi; float v[3];
        for(uint64_t o : all){ uint64_t it=r64(o+0x208);
            if(kname(it).empty()) continue; if(!entpos(o,v)) continue; keepi.push_back(o); }
        IT.swap(keepi);
        // noms : calcul une fois par item (cache)
        for(uint64_t o : IT){ if(NAMES.count(o)) continue;
            std::string nm; uint64_t it=r64(o+0x208); uint64_t q[96];
            if(it>=0x1000000 && rd(it,q,sizeof(q))){
                for(int j=2;j<96 && nm.empty();j++){ uint64_t w=q[j];
                    if(w<0x1000000||w>0x300000000000ULL) continue;
                    if(kname(w)=="ItemDefinition"){ std::string t=mstr(r64(w+0x28));
                        if(okname(t)) nm=t; } } }
            NAMES[o]= nm.empty()? std::string("item") : nm; }
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
static size_t nit(){ std::lock_guard<std::mutex> g(MTX); return IT.size(); }
static void refresher(){
    ls_regions(); discover_klasses();
    uint64_t t0=now_s(); pass(true); uint64_t last=now_s();
    printf("[v34] klasses BP=0x%llx PM=0x%llx DroppedItem=0x%llx | RW=%zu | complete %.1fs -> %zu joueurs, %zu items, %zu regions chaudes\n",
        (unsigned long long)KB.load(),(unsigned long long)KM.load(),(unsigned long long)KD.load(),RW.size(),
        (last-t0)/1000.0,nbp(),nit(),HOT.size()); fflush(stdout);
    for(;;){
        if((now_s()-last)/1000.0 >= FULL_PERIOD){ uint64_t s=now_s(); pass(true); last=now_s();
            printf("[v34] complete %.1fs -> %zu joueurs, %zu items\n",(last-s)/1000.0,nbp(),nit()); fflush(stdout); }
        else { uint64_t s=now_s(); pass(false); uint64_t e=now_s();
            if(e-s>800) printf("[v34] passe chaude lente %llu ms\n",(unsigned long long)(e-s)); }
        usleep(150000);
    }
}
int main(int argc,char**argv){
    if(argc>1) NT=atoi(argv[1]); if(argc>2) FULL_PERIOD=atof(argv[2]); if(argc>3) WRITE_PERIOD=atof(argv[3]);
    PID=0; { FILE* f=popen("pgrep -x Rust | head -1","r"); char b[64]; if(f&&fgets(b,64,f)) PID=atoi(b); if(f)pclose(f); }
    if(!PID){ printf("Rust absent\n"); return 1; }
    if(task_for_pid(mach_task_self(),PID,&T)!=KERN_SUCCESS){ printf("task_for_pid KO\n"); return 1; }
    printf("[v34] pid=%d threads=%d complete=%.1fs ecriture=%.2fs\n",PID,NT,FULL_PERIOD,WRITE_PERIOD); fflush(stdout);
    std::thread th(refresher); th.detach();
    for(;;){
        std::vector<uint64_t> bp, it; { std::lock_guard<std::mutex> g(MTX); bp=BP; it=IT; }
        std::vector<float> pos; std::vector<int> on_,wd; std::vector<uint64_t> ids;
        for(uint64_t o : bp){
            uint64_t m=r64(o+0x328); if(!m) continue;
            float v[3]; if(!rd(m+0x2F8,v,12)) continue;
            if(!std::isfinite(v[0])||!std::isfinite(v[1])||!std::isfinite(v[2])) continue;
            if(fabsf(v[0])>6000||fabsf(v[2])>6000) continue;
            if(v[1]<=0.5f||v[1]>900.0f) continue;
            if(fabsf(v[0])<1.0f&&fabsf(v[2])<1.0f) continue;
            uint32_t fl=0; if(!rd(o+0x6D8,&fl,4)) continue;
            pos.push_back(v[0]); pos.push_back(v[1]); pos.push_back(v[2]);
            on_.push_back((fl&0x100)?1:0); wd.push_back((fl&0x40)?1:0); ids.push_back(o);
        }
        size_t n=pos.size()/3; int onc=0; for(int x:on_) onc+=x;
        std::vector<float> ipos; std::vector<std::string> inm; std::vector<uint64_t> iid;
        for(uint64_t o : it){ float v[3]; if(!entpos(o,v)) continue;
            ipos.push_back(v[0]); ipos.push_back(v[1]); ipos.push_back(v[2]);
            std::string nm; { std::lock_guard<std::mutex> g(MTX); auto f=NAMES.find(o); nm = (f!=NAMES.end()? f->second : std::string("item")); }
            inm.push_back(nm); iid.push_back(o); }
        size_t ni=inm.size();
        char tmp[256]; snprintf(tmp,sizeof(tmp),"%s.tmp",OUT);
        FILE* f=fopen(tmp,"w");
        if(f){
            struct timespec rt; clock_gettime(CLOCK_REALTIME,&rt);
            fprintf(f,"{\"ts\":%.3f,\"count\":%zu,\"on\":%d,\"off\":%d,\"itemsN\":%zu,\"players\":[",
                rt.tv_sec+rt.tv_nsec/1e9,n,onc,(int)n-onc,ni);
            for(size_t i=0;i<n;i++)
                fprintf(f,"%s{\"x\":%.1f,\"y\":%.1f,\"z\":%.1f,\"on\":%d,\"w\":%d,\"id\":%llu}",i?",":"",
                    pos[i*3],pos[i*3+1],pos[i*3+2],on_[i],wd[i],(unsigned long long)ids[i]);
            fprintf(f,"],\"items\":[");
            for(size_t i=0;i<ni;i++)
                fprintf(f,"%s{\"x\":%.1f,\"y\":%.1f,\"z\":%.1f,\"n\":\"%s\",\"id\":%llu}",i?",":"",
                    ipos[i*3],ipos[i*3+1],ipos[i*3+2],inm[i].c_str(),(unsigned long long)iid[i]);
            fprintf(f,"]}"); fclose(f); rename(tmp,OUT);
        }
        usleep((useconds_t)(WRITE_PERIOD*1000000));
    }
}
