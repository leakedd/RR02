// probe_names2 — noms d'items RÉELS : validation par NOM de klass (pas par adresse).
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
static bool nat_at(uint64_t a,char*out,size_t n){ if(!rd(a,out,n-1)) return false; out[n-1]=0; if(!out[0]) return false;
    for(size_t i=0;out[i];i++) if((unsigned char)out[i]<0x20||(unsigned char)out[i]>0x7e) return false; return true; }
static std::string kname(uint64_t o){ if(o<0x1000000) return ""; uint64_t k=r64(o); if(k<0x1000000) return "";
    char b[80]={0}; uint64_t np=r64(k+0x10); if(!np||!nat_at(np,b,sizeof(b))) return ""; return std::string(b); }
static std::string mstr(uint64_t sp){ if(sp<0x1000000) return ""; int len=(int)r32(sp+0x10); char b[128]={0};
    if(len>0&&len<120&&nat_at(sp+0x14,b,(size_t)len+1)) return std::string(b);
    if(nat_at(sp+0x14,b,127)) return std::string(b); return ""; }
static std::string findnp(const char* pat){ // nom "..." via natif
    return std::string(pat); }
static bool plausible(const std::string&s){ if(s.size()<2||s.size()>48) return false;
    for(char c:s){ if(!((c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='.'||c=='_'||c=='-')) return false; } return true; }
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
    const char* WANT[]={"DroppedItem","DroppedItemContainer"};
    const int NW=2; uint64_t K[NW]={0};
    const size_t CH=8u<<20; std::vector<unsigned char> buf(CH);
    for(auto&r:R) for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+0x88<=(size_t)g;i+=8){ uint64_t X=c+i;
            if(*(uint64_t*)(buf.data()+i+0x78)!=X) continue;
            char nm[128]; uint64_t p=*(uint64_t*)(buf.data()+i+0x10); if(!p||!nat_at(p,nm,sizeof(nm))) continue;
            for(int k=0;k<NW;k++) if(!K[k]&&!strcmp(nm,WANT[k])) K[k]=X; } }
    uint64_t KD=K[0],KDC=K[1];
    printf("DroppedItem=0x%llx DroppedItemContainer=0x%llx (%.1f s)\n",(unsigned long long)KD,(unsigned long long)KDC,
        (double)clock()/CLOCKS_PER_SEC-t0);
    std::vector<uint64_t> refs;
    for(auto&r:R) for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+8<=(size_t)g;i+=8){ uint64_t v=*(uint64_t*)(buf.data()+i);
            if(v==KD||v==KDC) refs.push_back(c+i); } }
    printf("refs=%zu (%.1f s)\n",refs.size(),(double)clock()/CLOCKS_PER_SEC-t0);
    int valid=0, withItem=0, named=0, shown=0; std::map<int,int> defoff; std::map<std::string,int> tally;
    for(uint64_t a:refs){ uint64_t k=r64(a); if(k!=KD&&k!=KDC) continue;
        std::string kg=kname(r64(a+0x210)); if(kg!="GameObjectRef") continue;
        float p[3]={0,0,0}; if(!pathA(a,p)) continue; valid++;
        uint64_t it=r64(a+0x208); std::string ik=kname(it);
        if(ik.empty()||it<0x1000000){ if(shown<6){shown++; printf("  %s 0x%-11llx pos=(%9.2f %7.2f %9.2f) item=vide\n",
            k==KD?"ITEM":"BAG ",(unsigned long long)a,p[0],p[1],p[2]); } continue; }
        withItem++;
        // ItemDefinition : chercher dans les champs de l'objet Item
        uint64_t s[48]; if(!rd(it,s,sizeof(s))) continue;
        std::string sn; int iid=0,cat=0,off=-1;
        for(int j=2;j<48;j++){ uint64_t w=s[j]; if(w<0x1000000||w>0x300000000000ULL) continue;
            if(kname(w)=="ItemDefinition"){ std::string t=mstr(r64(w+0x28));
                if(plausible(t)){ sn=t; iid=(int)r32(w+0x20); cat=(int)r32(w+0x58); off=j*8; } } }
        if(off>=0) defoff[off]++;
        if(!sn.empty()){ named++; tally[sn]++; }
        if(shown<14){ shown++;
            printf("  %s 0x%-11llx pos=(%9.2f %7.2f %9.2f) item=%-10s %-26s id=%-6d cat=%-3d def@+0x%x\n",
                k==KD?"ITEM":"BAG ",(unsigned long long)a,p[0],p[1],p[2],ik.substr(0,9).c_str(),
                sn.empty()?"?":sn.c_str(),iid,cat,off); } }
    printf("\n-> valides=%d  avec Item=%d  nommes=%d\n",valid,withItem,named);
    printf("offsets ItemDefinition dans Item :"); for(auto&x:defoff) printf(" +0x%x x%d",x.first,x.second); printf("\n");
    printf("noms : "); for(auto&x:tally) printf("%s x%d | ",x.first.c_str(),x.second); printf("\n");
    printf("total %.1f s\n",(double)clock()/CLOCKS_PER_SEC-t0);
    return 0;
}
