// probe_diag — dump des champs d'un DroppedItem VIVANT avec le nom de klass de chaque pointeur.
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
static bool nat_at(uint64_t a,char*out,size_t n){ if(!rd(a,out,n-1)) return false; out[n-1]=0; if(!out[0]) return false;
    for(size_t i=0;out[i];i++) if((unsigned char)out[i]<0x20||(unsigned char)out[i]>0x7e) return false; return true; }
static std::string kname(uint64_t o){ if(o<0x1000000) return ""; uint64_t k=r64(o); if(k<0x1000000) return "";
    char b[80]={0}; uint64_t np=r64(k+0x10); if(!np||!nat_at(np,b,sizeof(b))) return "?"; return std::string(b); }
static std::string mstr(uint64_t strptr){ // chaîne managée IL2CPP : données à +0x14
    if(strptr<0x1000000) return ""; char b[96]={0};
    if(nat_at(strptr+0x14,b,sizeof(b))) return std::string(b);
    if(nat_at(strptr+0x10,b,sizeof(b))) return std::string(b);
    return ""; }
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
    const char* WANT[]={"DroppedItem","ItemDefinition","DroppedItemContainer"};
    const int NW=3; uint64_t K[NW]={0};
    const size_t CH=8u<<20; std::vector<unsigned char> buf(CH);
    for(auto&r:R) for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+0x88<=(size_t)g;i+=8){ uint64_t X=c+i;
            if(*(uint64_t*)(buf.data()+i+0x78)!=X) continue;
            char nm[128]; uint64_t p=*(uint64_t*)(buf.data()+i+0x10); if(!p||!nat_at(p,nm,sizeof(nm))) continue;
            for(int k=0;k<NW;k++) if(!K[k]&&!strcmp(nm,WANT[k])) K[k]=X; } }
    printf("DroppedItem=0x%llx ItemDefinition=0x%llx (%.1f s)\n",(unsigned long long)K[0],(unsigned long long)K[1],(double)clock()/CLOCKS_PER_SEC-t0);
    std::vector<uint64_t> refs;
    for(auto&r:R) for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+8<=(size_t)g;i+=8) if(*(uint64_t*)(buf.data()+i)==K[0]) refs.push_back(c+i); }
    int done=0;
    for(uint64_t a:refs){ if(done>=2) break; if(r64(a)!=K[0]) continue;
        float p[3]={0,0,0}; if(!pathA(a,p)) continue;
        printf("\n=== DroppedItem VIVANT obj=0x%llx pos=(%.2f %.2f %.2f) ===\n",(unsigned long long)a,p[0],p[1],p[2]);
        uint64_t q[96]; if(!rd(a,q,sizeof(q))) continue;
        for(int i=2;i<96;i++){ uint64_t v=q[i]; if(v<0x1000000||v>0x300000000000ULL) continue;
            std::string kn=kname(v); if(kn.empty()) continue;
            printf("  +0x%03x = 0x%llx  %s\n",i*8,(unsigned long long)v,kn.c_str());
            // 2e niveau : cet objet contient-il un ItemDefinition ?
            if(kn=="?"||kn.size()>30){ uint64_t s[48]; if(rd(v,s,sizeof(s))){
                for(int j=2;j<48;j++){ uint64_t w=s[j]; if(w<0x1000000||w>0x300000000000ULL) continue;
                    if(r64(w)==K[1]) printf("        ^^ +0x%x -> ItemDefinition ; shortname=\"%s\" itemid=%d\n",
                        j*8,(mstr(r64(w+0x28))).c_str(),(int)0); } } } }
        done++; }
    printf("\ntotal %.1f s\n",(double)clock()/CLOCKS_PER_SEC-t0);
    return 0;
}
