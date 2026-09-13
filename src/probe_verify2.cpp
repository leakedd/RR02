// probe_verify2 — pourquoi la chaîne échoue ? Cherche l'offset réel du Model par classe
// et nomme les klasses de la chaîne (Transform ou tableau).
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
#include <map>
#include <algorithm>
#include <ctime>

static task_t T;
static bool rd(uint64_t a,void*b,size_t n){ mach_vm_size_t g=0;
    return mach_vm_read_overwrite(T,a,n,(mach_vm_address_t)b,&g)==KERN_SUCCESS && g==n; }
static uint64_t r64(uint64_t a){ uint64_t v=0; rd(a,&v,8); return v; }
static bool str_at(uint64_t a,char*out,size_t n){ if(!rd(a,out,n-1)) return false; out[n-1]=0; if(!out[0]) return false;
    for(size_t i=0;out[i];i++) if((unsigned char)out[i]<0x20||(unsigned char)out[i]>0x7e) return false; return true; }
static std::string kname(uint64_t k){ char b[160]={0}; if(!k) return "?"; uint64_t np=r64(k+0x10); if(!np) return "?";
    if(!str_at(np,b,sizeof(b))) return "?"; return std::string(b); }
static bool sane(const float*v){ return std::isfinite(v[0])&&std::isfinite(v[1])&&std::isfinite(v[2])
    && fabsf(v[0])<6000&&fabsf(v[2])<6000&&v[1]>0.3f&&v[1]<900; }
struct Reg{ uint64_t a,sz; }; static std::vector<Reg> R;
static void regions(){ mach_vm_address_t a=0x100000000ULL;
    for(;;){ mach_vm_address_t q=a; mach_vm_size_t sz=0; vm_region_basic_info_data_64_t bi; mach_port_t ob=0;
        mach_msg_type_number_t ci=VM_REGION_BASIC_INFO_COUNT_64;
        if(mach_vm_region(T,&q,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&bi,&ci,&ob)!=KERN_SUCCESS) break;
        if(sz>0&&(bi.protection&VM_PROT_READ)&&(bi.protection&VM_PROT_WRITE)) R.push_back({q,sz});
        if(q+sz<=a) break; a=q+sz; } }
static bool chain(uint64_t obj,float*out,std::string*dbg=nullptr){
    std::string s;
    uint64_t m=r64(obj+0x1B8); if(m<0x1000000){ if(dbg)*dbg="model invalide"; return false; }
    s+="model("+kname(r64(m))+")";
    uint64_t tr=r64(m+0x28); if(tr<0x1000000){ if(dbg)*dbg=s+" rootBone invalide"; return false; }
    s+=" tr("+kname(r64(tr))+")";
    uint64_t nat=r64(tr+0x10); if(nat<0x1000000){ if(dbg)*dbg=s+" natif invalide"; return false; }
    s+=" nat=0x"+std::to_string((unsigned long long)nat);
    uint64_t d=r64(nat+0x28); if(d<0x1000000){ if(dbg)*dbg=s+" data invalide"; return false; }
    if(!rd(d+0x90,out,12)){ if(dbg)*dbg=s+" lecture KO"; return false; }
    if(!sane(out)){ if(dbg){ char b[128]; snprintf(b,sizeof(b)," pos non saine (%.2f %.2f %.2f)",out[0],out[1],out[2]); *dbg=s+b; } return false; }
    if(dbg)*dbg=s;
    return true; }
struct Cls{ const char* n; uint64_t k; };
int main(){
    setvbuf(stdout,NULL,_IONBF,0);
    double t0=(double)clock()/CLOCKS_PER_SEC;
    pid_t PID=0; { FILE* f=popen("pgrep -x Rust | head -1","r"); char b[64]; if(f&&fgets(b,64,f)) PID=atoi(b); if(f)pclose(f); }
    if(!PID||task_for_pid(mach_task_self(),PID,&T)!=KERN_SUCCESS){ printf("task_for_pid KO\n"); return 1; }
    regions();
    Cls C[]={{"BasePlayer",0x10466cdb0ULL},{"Model",0x12895e6e0ULL},{"PlayerCorpse",0x129b01530ULL},
             {"LootContainer",0x12868d200ULL},{"DroppedItem",0x10462f0f0ULL},
             {"DroppedItemContainer",0x1288eaf10ULL},{"HackableLockedCrate",0x1289983a0ULL},
             {"SupplyDrop",0x1288499b0ULL},{"BaseCorpse",0x1286106e0ULL},{"StashContainer",0x1297f1740ULL}};
    const int NC=10; uint64_t KM=C[1].k;
    const size_t CH=8u<<20; std::vector<unsigned char> buf(CH);
    std::vector<std::vector<uint64_t>> hits(NC);
    for(auto&r:R) for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+8<=(size_t)g;i+=8){ uint64_t v=*(uint64_t*)(buf.data()+i);
            for(int k=0;k<NC;k++) if(v==C[k].k){ hits[k].push_back(c+i); break; } } }
    printf("balayage fini %.1f s\n\n",(double)clock()/CLOCKS_PER_SEC-t0);
    for(int k=2;k<NC;k++){
        std::map<int,int> offhist; int inst=0, live=0, moff_found=0; int model_off=-1;
        printf("=== %s === (refs %zu)\n",C[k].n,hits[k].size());
        for(uint64_t a:hits[k]){ if(inst>=12) break; if(r64(a)!=C[k].k) continue;
            inst++;
            // offsets où un objet de klass Model est référencé
            int found=-1;
            uint64_t q[64]; if(!rd(a,q,sizeof(q))) continue;
            for(int i=2;i<64;i++){ uint64_t p=q[i]; if(p<0x1000000||p>0x300000000000ULL) continue;
                if(r64(p)==KM){ offhist[i*8]++; if(found<0) found=i*8; } }
            float v[3]={0,0,0}; std::string dbg; bool ok=chain(a,v,&dbg);
            if(ok) live++;
            if(found>=0){ moff_found++; if(model_off<0) model_off=found; }
            if(inst<=4 || ok) printf("  obj=0x%-11llx model@%s chaine=%s%s\n",(unsigned long long)a,
                found>=0?("+0x"+std::to_string(found)).c_str():"aucun",
                ok?"OK ":"KO ", ok?("pos=("+std::to_string((int)v[0])+","+std::to_string((int)v[1])+","+std::to_string((int)v[2])+")").c_str():dbg.c_str());
        }
        printf("  -> %d objets, %d avec Model, %d chaine OK ; offsets Model:",inst,moff_found,live);
        for(auto&pr:offhist) printf(" +0x%x×%d",pr.first,pr.second);
        printf("\n\n");
    }
    printf("total %.1f s\n",(double)clock()/CLOCKS_PER_SEC-t0);
    return 0;
}
