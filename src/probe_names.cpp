// probe_names — noms des items au sol :
//   DroppedItem -> chemin A pour la position -> champ Item (0x10..0x300) -> ItemDefinition+0xD8
//   -> shortname (ItemDefinition+0x28) + itemid (+0x20) + category (+0x58)
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
static uint32_t r32(uint64_t a){ uint32_t v=0; rd(a,&v,4); return v; }
static bool str_at(uint64_t a,char*out,size_t n){ if(!rd(a,out,n-1)) return false; out[n-1]=0; if(!out[0]) return false;
    for(size_t i=0;out[i];i++) if((unsigned char)out[i]<0x20||(unsigned char)out[i]>0x7e) return false; return true; }
static bool sane(const float*v){ return std::isfinite(v[0])&&std::isfinite(v[1])&&std::isfinite(v[2])
    && fabsf(v[0])<6000&&fabsf(v[2])<6000&&v[1]>0.2f&&v[1]<900; }
static bool pathA(uint64_t o,float*out){ uint64_t h=r64(o+0x90); if(h<0x1000000) return false;
    uint64_t d=r64(h+0x00); if(d<0x1000000) return false;
    if(!rd(d+0x90,out,12)) return false; return sane(out); }
struct Reg{ uint64_t a,sz; }; static std::vector<Reg> R;
static void regions(){ mach_vm_address_t a=0x100000000ULL;
    for(;;){ mach_vm_address_t q=a; mach_vm_size_t sz=0; vm_region_basic_info_data_64_t bi; mach_port_t ob=0;
        mach_msg_type_number_t ci=VM_REGION_BASIC_INFO_COUNT_64;
        if(mach_vm_region(T,&q,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&bi,&ci,&ob)!=KERN_SUCCESS) break;
        if(sz>0&&(bi.protection&VM_PROT_READ)&&(bi.protection&VM_PROT_WRITE)) R.push_back({q,sz});
        if(q+sz<=a) break; a=q+sz; } }
int main(){
    setvbuf(stdout,NULL,_IONBF,0);
    double t0=(double)clock()/CLOCKS_PER_SEC;
    pid_t PID=0; { FILE* f=popen("pgrep -x Rust | head -1","r"); char b[64]; if(f&&fgets(b,64,f)) PID=atoi(b); if(f)pclose(f); }
    if(!PID||task_for_pid(mach_task_self(),PID,&T)!=KERN_SUCCESS){ printf("task_for_pid KO\n"); return 1; }
    regions();
    const char* WANT[]={"DroppedItem","DroppedItemContainer","ItemDefinition"};
    const int NW=3; uint64_t K[NW]={0};
    const size_t CH=8u<<20; std::vector<unsigned char> buf(CH);
    for(auto&r:R) for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+0x88<=(size_t)g;i+=8){ uint64_t X=c+i;
            if(*(uint64_t*)(buf.data()+i+0x78)!=X) continue;
            char nm[128]; uint64_t p=*(uint64_t*)(buf.data()+i+0x10); if(!p||!str_at(p,nm,sizeof(nm))) continue;
            for(int k=0;k<NW;k++) if(!K[k]&&!strcmp(nm,WANT[k])) K[k]=X; } }
    printf("klasses : DroppedItem=0x%llx DroppedItemContainer=0x%llx ItemDefinition=0x%llx (%.1f s)\n",
        (unsigned long long)K[0],(unsigned long long)K[1],(unsigned long long)K[2],(double)clock()/CLOCKS_PER_SEC-t0);
    uint64_t KD=K[0],KDC=K[1],KID=K[2];
    std::vector<uint64_t> refs;
    for(auto&r:R) for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+8<=(size_t)g;i+=8){ uint64_t v=*(uint64_t*)(buf.data()+i);
            if(v==KD||v==KDC) refs.push_back(c+i); } }
    printf("refs items = %zu (%.1f s)\n\n",refs.size(),(double)clock()/CLOCKS_PER_SEC-t0);
    std::map<int,int> offhist; int live=0, named=0, shown=0;
    std::map<std::string,int> tally;
    for(uint64_t a:refs){ uint64_t k=r64(a); if(k!=KD&&k!=KDC) continue;
        float p[3]={0,0,0}; bool ok=pathA(a,p); if(!ok) continue; live++;
        // cherche le champ Item : pointeur p2 tel que r64(r64(p2+0xD8)) == ItemDefinition
        uint64_t q[96]; if(!rd(a,q,sizeof(q))) continue;
        std::string name; int off=-1; int iid=0,cat=0;
        for(int i=2;i<96;i++){ uint64_t v=q[i]; if(v<0x1000000||v>0x300000000000ULL) continue;
            uint64_t def=r64(v+0xD8); if(def<0x1000000) continue;
            if(r64(def)!=KID) continue;
            char sn[64]={0}; if(!str_at(r64(def+0x28)?r64(def+0x28):0,sn,sizeof(sn))) continue;
            // r64(def+0x28) est le pointeur de chaîne ; str_at attend l'adresse de la chaîne
            name=sn; off=i*8; iid=(int)r32(def+0x20); cat=(int)r32(def+0x58); break; }
        if(off>=0){ offhist[off]++; }
        if(!name.empty()){ named++; tally[name]++; }
        if(shown<25 && !name.empty()){ shown++;
            printf("  obj=0x%-11llx pos=(%9.2f %7.2f %9.2f) %-28s itemid=%-6d cat=%d (champ +0x%x)\n",
                (unsigned long long)a,p[0],p[1],p[2],name.c_str(),iid,cat,off); }
    }
    printf("\n-> instances vivantes=%d  noms lus=%d\n",live,named);
    printf("offsets du champ Item :"); for(auto&pr:offhist) printf(" +0x%x x%d",pr.first,pr.second); printf("\n");
    printf("items distincts : "); for(auto&pr:tally) printf("%s x%d | ",pr.first.c_str(),pr.second); printf("\n");
    printf("total %.1f s\n",(double)clock()/CLOCKS_PER_SEC-t0);
    return 0;
}
