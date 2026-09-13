// probe_itemstrings — les instances de la classe Item donnent-elles des shortnames propres ?
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
// string managée : longueur en int32 à +0x10, caractères à +0x14
static std::string mstr(uint64_t sp){ if(sp<0x1000000) return ""; int len=(int)r32(sp+0x10);
    char b[128]={0}; if(len>0&&len<120&&nat_at(sp+0x14,b,(size_t)len+1)) return std::string(b);
    if(nat_at(sp+0x14,b,127)) return std::string(b);
    if(nat_at(sp+0x10,b,127)) return std::string(b); return ""; }
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
    const char* WANT[]={"ItemDefinition","%842e6b2f32a12d6d9f1a80e7de9e9902d2f3ecdc","DroppedItem"};
    const int NW=3; uint64_t K[NW]={0};
    const size_t CH=8u<<20; std::vector<unsigned char> buf(CH);
    for(auto&r:R) for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+0x88<=(size_t)g;i+=8){ uint64_t X=c+i;
            if(*(uint64_t*)(buf.data()+i+0x78)!=X) continue;
            char nm[128]; uint64_t p=*(uint64_t*)(buf.data()+i+0x10); if(!p||!nat_at(p,nm,sizeof(nm))) continue;
            for(int k=0;k<NW;k++) if(!K[k]&&!strcmp(nm,WANT[k])) K[k]=X; } }
    uint64_t KID=K[0],KIT=K[1],KD=K[2];
    printf("ItemDefinition=0x%llx Item=0x%llx DroppedItem=0x%llx (%.1f s)\n",
        (unsigned long long)KID,(unsigned long long)KIT,(unsigned long long)KD,(double)clock()/CLOCKS_PER_SEC-t0);
    // d'abord : les ItemDefinition elles-mêmes -> leurs shortnames (contrôle du layout String)
    std::vector<uint64_t> refid;
    for(auto&r:R) for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+8<=(size_t)g;i+=8){ uint64_t v=*(uint64_t*)(buf.data()+i);
            if(v==KID||v==KIT) refid.push_back((v==KID)?c+i:c+i); } }
    printf("refs ItemDefinition+Item = %zu (%.1f s)\n",refid.size(),(double)clock()/CLOCKS_PER_SEC-t0);
    int ndef=0, shown=0; std::map<std::string,int> tally;
    for(uint64_t a:refid){ uint64_t k=r64(a);
        if(k==KID){ ndef++;
            std::string sn=mstr(r64(a+0x28)); int iid=(int)r32(a+0x20);
            if(!sn.empty()) tally[sn]++;
            if(shown<25 && !sn.empty()){ shown++;
                printf("  DEF 0x%-11llx shortname=%-28s itemid=%d\n",(unsigned long long)a,sn.c_str(),iid); } } }
    printf("\n-> %d refs ItemDefinition ; %zu noms distincts\n",ndef,tally.size());
    printf("echantillon : "); int c=0; for(auto&pr:tally){ printf("'%s' ",pr.first.c_str()); if(++c>25) break; } printf("\n");
    printf("total %.1f s\n",(double)clock()/CLOCKS_PER_SEC-t0);
    return 0;
}
