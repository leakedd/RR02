// probe_v3 — deux chemins de position, uniquement sur de VRAIES instances.
//  A: obj+0x90 (TransformHandle.pTransformData) -> [0] -> +0x90
//  B: obj+0x1B8 (Model) -> +0x28 (Transform) -> +0x10 (natif) -> +0x28 -> +0x90
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cmath>
#include <vector>
#include <string>
#include <algorithm>
#include <ctime>

static task_t T;
static bool rd(uint64_t a,void*b,size_t n){ mach_vm_size_t g=0;
    return mach_vm_read_overwrite(T,a,n,(mach_vm_address_t)b,&g)==KERN_SUCCESS && g==n; }
static uint64_t r64(uint64_t a){ uint64_t v=0; rd(a,&v,8); return v; }
static bool str_at(uint64_t a,char*out,size_t n){ if(!rd(a,out,n-1)) return false; out[n-1]=0; if(!out[0]) return false;
    for(size_t i=0;out[i];i++) if((unsigned char)out[i]<0x20||(unsigned char)out[i]>0x7e) return false; return true; }
static std::string kname(uint64_t k){ char b[160]={0}; if(!k) return "?"; uint64_t np=r64(k+0x10);
    if(!np||!str_at(np,b,sizeof(b))) return "?"; return std::string(b); }
static bool sane(const float*v){ return std::isfinite(v[0])&&std::isfinite(v[1])&&std::isfinite(v[2])
    && fabsf(v[0])<6000&&fabsf(v[2])<6000&&v[1]>0.3f&&v[1]<900; }
struct Reg{ uint64_t a,sz; }; static std::vector<Reg> R;
static void regions(){ mach_vm_address_t a=0x100000000ULL;
    for(;;){ mach_vm_address_t q=a; mach_vm_size_t sz=0; vm_region_basic_info_data_64_t bi; mach_port_t ob=0;
        mach_msg_type_number_t ci=VM_REGION_BASIC_INFO_COUNT_64;
        if(mach_vm_region(T,&q,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&bi,&ci,&ob)!=KERN_SUCCESS) break;
        if(sz>0&&(bi.protection&VM_PROT_READ)&&(bi.protection&VM_PROT_WRITE)) R.push_back({q,sz});
        if(q+sz<=a) break; a=q+sz; } }
static bool pathA(uint64_t o,float*out,std::string*dbg){ uint64_t h=r64(o+0x90);
    if(h<0x1000000){ if(dbg)*dbg="handle invalide"; return false; }
    uint64_t d=r64(h+0x00); if(d<0x1000000){ if(dbg)*dbg="h[0] invalide"; return false; }
    if(!rd(d+0x90,out,12)){ if(dbg)*dbg="lecture KO"; return false; }
    if(!sane(out)){ if(dbg){char b[96];snprintf(b,sizeof(b),"pos non saine (%.2f %.2f %.2f)",out[0],out[1],out[2]);*dbg=b;} return false; }
    if(dbg)*dbg="ok"; return true; }
static bool pathB(uint64_t o,float*out,std::string*dbg){ uint64_t m=r64(o+0x1B8);
    if(m<0x1000000){ if(dbg)*dbg="model invalide"; return false; }
    uint64_t tr=r64(m+0x28); if(tr<0x1000000){ if(dbg)*dbg="rootBone invalide"; return false; }
    uint64_t nat=r64(tr+0x10); if(nat<0x1000000){ if(dbg)*dbg="natif invalide"; return false; }
    uint64_t d=r64(nat+0x28); if(d<0x1000000){ if(dbg)*dbg="data invalide"; return false; }
    if(!rd(d+0x90,out,12)){ if(dbg)*dbg="lecture KO"; return false; }
    if(!sane(out)){ if(dbg){char b[96];snprintf(b,sizeof(b),"pos non saine (%.2f %.2f %.2f)",out[0],out[1],out[2]);*dbg=b;} return false; }
    if(dbg)*dbg="ok"; return true; }
struct Cls{ const char* n; uint64_t k; };
int main(){
    setvbuf(stdout,NULL,_IONBF,0);
    double t0=(double)clock()/CLOCKS_PER_SEC;
    pid_t PID=0; { FILE* f=popen("pgrep -x Rust | head -1","r"); char b[64]; if(f&&fgets(b,64,f)) PID=atoi(b); if(f)pclose(f); }
    if(!PID||task_for_pid(mach_task_self(),PID,&T)!=KERN_SUCCESS){ printf("task_for_pid KO\n"); return 1; }
    regions();
    Cls C[]={{"BasePlayer",0x10466cdb0ULL},{"PlayerModel",0x129a2abd0ULL},{"Model",0x12895e6e0ULL},
             {"PlayerCorpse",0x129b01530ULL},{"LootContainer",0x12868d200ULL},{"DroppedItem",0x10462f0f0ULL},
             {"DroppedItemContainer",0x1288eaf10ULL},{"HackableLockedCrate",0x1289983a0ULL},
             {"SupplyDrop",0x1288499b0ULL},{"BaseCorpse",0x1286106e0ULL},{"StashContainer",0x1297f1740ULL}};
    const int NC=11; uint64_t KM=C[2].k,KP=C[0].k,KPM=C[1].k;
    const size_t CH=8u<<20; std::vector<unsigned char> buf(CH);
    std::vector<std::vector<uint64_t>> hits(NC);
    for(auto&r:R) for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+8<=(size_t)g;i+=8){ uint64_t v=*(uint64_t*)(buf.data()+i);
            for(int k=0;k<NC;k++) if(v==C[k].k){ hits[k].push_back(c+i); break; } } }
    printf("balayage %.1f s\n",(double)clock()/CLOCKS_PER_SEC-t0);
    // joueurs en premier : contrôle des 2 chemins contre la vérité terrain
    printf("\n=== JOUEURS (controle) ===\n"); int nb=0;
    for(uint64_t a:hits[0]){ if(nb>=5) break; if(r64(a)!=KP) continue;
        uint64_t p=r64(a+0x328); if(p<0x1000000||r64(p)!=KPM) continue;
        float v[3]; if(!rd(p+0x2F8,v,12)||!sane(v)) continue;
        float x[3]={0,0,0},y[3]={0,0,0}; std::string da,db;
        bool oka=pathA(a,x,&da), okb=pathB(a,y,&db);
        float ea=oka?sqrtf((x[0]-v[0])*(x[0]-v[0])+(x[1]-v[1])*(x[1]-v[1])+(x[2]-v[2])*(x[2]-v[2])):-1;
        float eb=okb?sqrtf((y[0]-v[0])*(y[0]-v[0])+(y[1]-v[1])*(y[1]-v[1])+(y[2]-v[2])*(y[2]-v[2])):-1;
        printf("  verite=(%.1f %.1f %.1f) A=%s ecart=%.3f | B=%s ecart=%.3f\n",v[0],v[1],v[2],
            oka?"OK":"KO",ea,okb?"OK":"KO",eb); nb++; }
    for(int k=2;k<NC;k++){
        int nref=hits[k].size(), inst=0, wm=0, oa=0, ob=0, shown=0;
        printf("\n=== %s (refs %d) ===\n",C[k].n,nref);
        for(uint64_t a:hits[k]){ if(r64(a)!=C[k].k) continue;
            uint64_t m=r64(a+0x1B8); bool hasm=(m>=0x1000000&&r64(m)==KM);
            if(!hasm && inst>4000) continue;
            inst++; if(hasm) wm++;
            float x[3]={0,0,0},y[3]={0,0,0}; std::string da,db;
            bool oka=pathA(a,x,&da), okb=hasm?pathB(a,y,&db):false;
            if(oka) oa++; if(okb) ob++;
            if(shown<3 && (hasm||oka)){ shown++;
                printf("  obj=0x%-11llx model=%s A=%s%s B=%s%s\n",(unsigned long long)a,hasm?"oui":"non",
                    oka?"OK":"KO",oka?(""+std::to_string((int)x[0])+","+std::to_string((int)x[1])+","+std::to_string((int)x[2])).c_str():(" ["+da+"]").c_str(),
                    okb?"OK":"KO",okb?(""+std::to_string((int)y[0])+","+std::to_string((int)y[1])+","+std::to_string((int)y[2])).c_str():(" ["+(hasm?db:std::string("pas de model"))+"]").c_str()); } }
        printf("  -> candidats=%d  avec Model=%d  cheminA OK=%d  cheminB OK=%d\n",inst,wm,oa,ob);
    }
    printf("\ntotal %.1f s\n",(double)clock()/CLOCKS_PER_SEC-t0);
    return 0;
}
