// probe_items_final — test d'instance FORT pour DroppedItem :
//   r64(a)==klass ET r64(r64(a+0x208))==klass Item  (champ WorldItem.item)
//   position via chemin A (obj+0x90 -> [0] -> +0x90)
//   nom via Item+0xD8 -> ItemDefinition ; shortname = string managée (+0x14)
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
static std::string mstr(uint64_t sp){ if(sp<0x1000000) return ""; char b[96]={0};
    if(nat_at(sp+0x14,b,sizeof(b))) return std::string(b);
    if(nat_at(sp+0x10,b,sizeof(b))) return std::string(b); return ""; }
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
    const char* WANT[]={"DroppedItem","DroppedItemContainer","GameObjectRef","ItemDefinition",
                        "%842e6b2f32a12d6d9f1a80e7de9e9902d2f3ecdc"};
    const int NW=5; uint64_t K[NW]={0};
    const size_t CH=8u<<20; std::vector<unsigned char> buf(CH);
    for(auto&r:R) for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+0x88<=(size_t)g;i+=8){ uint64_t X=c+i;
            if(*(uint64_t*)(buf.data()+i+0x78)!=X) continue;
            char nm[128]; uint64_t p=*(uint64_t*)(buf.data()+i+0x10); if(!p||!nat_at(p,nm,sizeof(nm))) continue;
            for(int k=0;k<NW;k++) if(!K[k]&&!strcmp(nm,WANT[k])) K[k]=X; } }
    printf("DroppedItem=0x%llx DroppedItemContainer=0x%llx GameObjectRef=0x%llx ItemDefinition=0x%llx Item(classe)=0x%llx  (%.1f s)\n",
        (unsigned long long)K[0],(unsigned long long)K[1],(unsigned long long)K[2],(unsigned long long)K[3],
        (unsigned long long)K[4],(double)clock()/CLOCKS_PER_SEC-t0);
    uint64_t KD=K[0],KDC=K[1],KGOR=K[2],KID=K[3],KIT=K[4];
    std::vector<uint64_t> refs;
    for(auto&r:R) for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+8<=(size_t)g;i+=8){ uint64_t v=*(uint64_t*)(buf.data()+i);
            if(v==KD||v==KDC) refs.push_back(c+i); } }
    printf("refs=%zu (%.1f s)\n",refs.size(),(double)clock()/CLOCKS_PER_SEC-t0);
    int cand=0, viaItem=0, viaGOR=0, withPos=0, named=0, shown=0;
    std::map<std::string,int> tally;
    for(uint64_t a:refs){ uint64_t k=r64(a); if(k!=KD&&k!=KDC) continue; cand++;
        uint64_t it=r64(a+0x208), gor=r64(a+0x210);
        bool okI=(it>=0x1000000&&r64(it)==KIT), okG=(gor>=0x1000000&&r64(gor)==KGOR);
        if(!okI&&!okG) continue;
        if(okI) viaItem++; if(okG) viaGOR++;
        float p[3]={0,0,0}; if(!pathA(a,p)) continue; withPos++;
        std::string name; int iid=0;
        if(okI){ uint64_t def=r64(it+0xD8); if(def>=0x1000000&&r64(def)==KID){
            name=mstr(r64(def+0x28)); iid=(int)r32(def+0x20); } }
        if(!name.empty()){ named++; tally[name]++; }
        if(shown<20){ shown++;
            printf("  %s obj=0x%-11llx pos=(%9.2f %7.2f %9.2f) %-24s (%s%s)\n",
                k==KD?"ITEM":"BAG ",
                (unsigned long long)a,p[0],p[1],p[2],name.empty()?"?":name.c_str(),
                okI?"item->ItemDefinition":"", okG?" +GameObjectRef":""); } }
    printf("\n-> candidats=%d  item-ok=%d  gor-ok=%d  position-ok=%d  nom=%d\n",cand,viaItem,viaGOR,withPos,named);
    printf("items distincts : "); for(auto&pr:tally) printf("%s x%d | ",pr.first.c_str(),pr.second); printf("\n");
    printf("total %.1f s\n",(double)clock()/CLOCKS_PER_SEC-t0);
    return 0;
}
