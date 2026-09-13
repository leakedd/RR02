// probe_diag2 — champs d'une instance DroppedItem VALIDÉE par le test GameObjectRef.
// Objectif : localiser le champ Item (nom d'arme) et lire un shortname plausible.
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
static uint32_t r32(uint64_t a){ uint32_t v=0; rd(a,&v,4); return v; }
static bool nat_at(uint64_t a,char*out,size_t n){ if(!rd(a,out,n-1)) return false; out[n-1]=0; if(!out[0]) return false;
    for(size_t i=0;out[i];i++) if((unsigned char)out[i]<0x20||(unsigned char)out[i]>0x7e) return false; return true; }
static std::string kname(uint64_t o){ if(o<0x1000000) return ""; uint64_t k=r64(o); if(k<0x1000000) return "";
    char b[80]={0}; uint64_t np=r64(k+0x10); if(!np||!nat_at(np,b,sizeof(b))) return "?"; return std::string(b); }
static std::string mstr(uint64_t sp){ if(sp<0x1000000) return ""; int len=(int)r32(sp+0x10); char b[128]={0};
    if(len>0&&len<120&&nat_at(sp+0x14,b,(size_t)len+1)) return std::string(b);
    if(nat_at(sp+0x14,b,127)) return std::string(b); return ""; }
static bool plausible(const std::string&s){ if(s.size()<2||s.size()>40) return false;
    for(char c:s){ if(!( (c>='a'&&c<='z')||(c>='0'&&c<='9')||c=='.'||c=='_'||c=='-')) return false; } return true; }
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
    const char* WANT[]={"DroppedItem","GameObjectRef","ItemDefinition","%842e6b2f32a12d6d9f1a80e7de9e9902d2f3ecdc"};
    const int NW=4; uint64_t K[NW]={0};
    const size_t CH=8u<<20; std::vector<unsigned char> buf(CH);
    for(auto&r:R) for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+0x88<=(size_t)g;i+=8){ uint64_t X=c+i;
            if(*(uint64_t*)(buf.data()+i+0x78)!=X) continue;
            char nm[128]; uint64_t p=*(uint64_t*)(buf.data()+i+0x10); if(!p||!nat_at(p,nm,sizeof(nm))) continue;
            for(int k=0;k<NW;k++) if(!K[k]&&!strcmp(nm,WANT[k])) K[k]=X; } }
    printf("DroppedItem=0x%llx GOR=0x%llx ItemDef=0x%llx Item=0x%llx (%.1f s)\n",
        (unsigned long long)K[0],(unsigned long long)K[1],(unsigned long long)K[2],(unsigned long long)K[3],
        (double)clock()/CLOCKS_PER_SEC-t0);
    uint64_t KD=K[0],KGOR=K[1],KID=K[2],KIT=K[3];
    std::vector<uint64_t> refs;
    for(auto&r:R) for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+8<=(size_t)g;i+=8) if(*(uint64_t*)(buf.data()+i)==KD) refs.push_back(c+i); }
    printf("refs DroppedItem=%zu (%.1f s)\n",refs.size(),(double)clock()/CLOCKS_PER_SEC-t0);
    int done=0, nval=0;
    for(uint64_t a:refs){ if(done>=3) break; if(r64(a)!=KD) continue;
        uint64_t gor=r64(a+0x210); if(!(gor>=0x1000000&&r64(gor)==KGOR)) continue;
        float p[3]={0,0,0}; if(!pathA(a,p)) continue; nval++;
        printf("\n=== DroppedItem VALIDE obj=0x%llx pos=(%.2f %.2f %.2f) ===\n",(unsigned long long)a,p[0],p[1],p[2]);
        uint64_t q[96]; if(!rd(a,q,sizeof(q))) continue;
        printf("  raw 0x1f0..0x240 :"); for(int i=62;i<72;i++) printf(" %llx",(unsigned long long)q[i]); printf("\n");
        for(int i=2;i<96;i++){ uint64_t v=q[i]; if(v<0x1000000||v>0x300000000000ULL) continue;
            std::string kn=kname(v); if(kn.empty()) continue;
            printf("  +0x%03x = 0x%llx  %s",i*8,(unsigned long long)v,kn.c_str());
            if(kn.size()>25||kn=="?"){ // objet interne : contient-il un ItemDefinition ?
                uint64_t s[32]; if(rd(v,s,sizeof(s))){ for(int j=0;j<32;j++){ uint64_t w=s[j];
                    if(w<0x1000000||w>0x300000000000ULL) continue;
                    if(r64(w)==KIT) printf("  [Item@+0x%x]",j*8);
                    if(r64(w)==KID){ std::string sn=mstr(r64(w+0x28));
                        if(plausible(sn)) printf("  [ItemDef@+0x%x shortname='%s' id=%d]",j*8,sn.c_str(),(int)r32(w+0x20)); } } } }
            printf("\n"); }
        done++; }
    printf("\n-> instances valides vues=%d\n",nval);
    printf("total %.1f s\n",(double)clock()/CLOCKS_PER_SEC-t0);
    return 0;
}
