// chain_find2 — cherche la liste d'entités à partir du struct de classe, validée par homogénéité :
//   klass+o1 -> sf ; sf+o2 -> wrapper ; wrapper+o3 -> set ; set+co = count, set+ao = array ;
//   éléments = arr+base+8j -> objets ; critère : >=4 pointeurs valides ET classe dominante >=70%
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>
#include <map>
#include <cmath>
static task_t T=MACH_PORT_NULL;
static bool rd(uint64_t a,void*b,size_t n){mach_vm_size_t g=0;return mach_vm_read_overwrite(T,a,n,(mach_vm_address_t)b,&g)==KERN_SUCCESS&&g==n;}
static uint64_t r64(uint64_t a){uint64_t v=0;rd(a,&v,8);return v;}
static uint32_t r32(uint64_t a){uint32_t v=0;rd(a,&v,4);return v;}
static bool pok(uint64_t p){return p>0x1000000&&p<0x800000000000ULL&&!(p&7);}
static bool wv(uint64_t o,uint64_t off){float v[3]={};if(!rd(o+off,v,12))return false;
  return std::isfinite(v[0])&&std::isfinite(v[1])&&std::isfinite(v[2])&&fabsf(v[0])<5000&&fabsf(v[2])<5000&&v[1]>-200&&v[1]<1200;}
int main(int argc,char**argv){
    uint64_t KL=strtoull(argv[1],nullptr,16);
    int bytes=proc_listpids(PROC_ALL_PIDS,0,nullptr,0);
    std::vector<pid_t> ps(bytes/4+256);bytes=proc_listpids(PROC_ALL_PIDS,0,ps.data(),ps.size()*4);
    pid_t pid=0;for(int i=0;i<bytes/4;i++){char p[PROC_PIDPATHINFO_MAXSIZE]={};if(proc_pidpath(ps[i],p,sizeof p)>0&&strstr(p,"/RustClient.app/Contents/MacOS/Rust")){pid=ps[i];break;}}
    if(task_for_pid(mach_task_self(),pid,&T)!=KERN_SUCCESS){printf("TFP_FAIL\n");return 1;}
    printf("classe=0x%llx\n",(unsigned long long)KL);
    int sol=0;
    uint64_t o1r[]={0x40,0x40+8};
    for(uint64_t o1=0x40;o1<=0x300;o1+=8){
        uint64_t sf=r64(KL+o1);if(!pok(sf))continue;
        for(uint64_t o2=0;o2<=0x60;o2+=8){
            uint64_t wr=r64(sf+o2);if(!pok(wr))continue;
            for(uint64_t o3=0;o3<=0x60;o3+=8){
                uint64_t set=r64(wr+o3);if(!pok(set))continue;
                struct{int co,ao;}V[]={{0x18,0x10},{0x10,0x18},{0x18,0x20},{0x20,0x18},{0x1C,0x10},{0x10,0x20}};
                for(auto&v:V){
                    uint32_t cnt=r32(set+v.co);if(cnt<4||cnt>500)continue;
                    uint64_t arr=r64(set+v.ao);if(!pok(arr))continue;
                    std::map<uint64_t,int> kl;int valid=0;uint64_t sample=0;bool posok=false;
                    for(uint32_t j=0;j<cnt&&j<40;j++){
                        uint64_t el=r64(arr+0x20+8*j);if(!pok(el))continue;
                        valid++;uint64_t k=r64(el);kl[k]++;
                        if(!sample){sample=el;}
                        if(wv(el,0x2F8)||wv(el,0x304)||wv(el,0x310))posok=true;
                    }
                    if(valid<4)continue;
                    int best=0;uint64_t bk=0;for(auto&x:kl)if(x.second>best){best=x.second;bk=x.first;}
                    if(best*100/valid>=70){
                        printf("  CANDIDAT o1=klass+0x%llx wrap=sf+0x%llx set=wr+0x%llx count@+0x%x=%u arr@+0x%x "
                               "valid=%d classe_dominante=0x%llx (%d/%d) pos_plausible=%d\n",
                               (unsigned long long)o1,(unsigned long long)o2,(unsigned long long)o3,
                               v.co,cnt,v.ao,valid,(unsigned long long)bk,best,valid,(int)posok);
                        sol++;
                    }
                }
            }
        }
    }
    printf("total: %d\n",sol);
    return 0;
}
