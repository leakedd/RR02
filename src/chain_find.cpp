// chain_find — à partir d'un klass PlayerModel, retrouve la chaîne static_fields -> wrapper -> ListHashSet
// par brute force des offsets, validée par auto-cohérence (les éléments du set pointent des objets du même klass)
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>
#include <cmath>
static task_t T=MACH_PORT_NULL;
static bool rd(uint64_t a,void*b,size_t n){mach_vm_size_t g=0;return mach_vm_read_overwrite(T,a,n,(mach_vm_address_t)b,&g)==KERN_SUCCESS&&g==n;}
static uint64_t r64(uint64_t a){uint64_t v=0;rd(a,&v,8);return v;}
static uint32_t r32(uint64_t a){uint32_t v=0;rd(a,&v,4);return v;}
static bool ptr_ok(uint64_t p){return p>0x1000000&&p<0x800000000000ULL&&!(p&7);}
static bool worldvec(uint64_t obj,uint64_t off){float v[3]={};if(!rd(obj+off,v,12))return false;
  return std::isfinite(v[0])&&std::isfinite(v[1])&&std::isfinite(v[2])&&fabs(v[0])<5000&&fabs(v[2])<5000&&v[1]>-200&&v[1]<1200;}
int main(int argc,char**argv){
    uint64_t klass=strtoull(argv[1],nullptr,16);
    uint64_t posoff=argc>2?strtoull(argv[2],nullptr,16):0x2F8;
    int bytes=proc_listpids(PROC_ALL_PIDS,0,nullptr,0);
    std::vector<pid_t> ps(bytes/4+256);bytes=proc_listpids(PROC_ALL_PIDS,0,ps.data(),ps.size()*4);
    pid_t pid=0;for(int i=0;i<bytes/4;i++){char p[PROC_PIDPATHINFO_MAXSIZE]={};if(proc_pidpath(ps[i],p,sizeof p)>0&&strstr(p,"/RustClient.app/Contents/MacOS/Rust")){pid=ps[i];break;}}
    if(task_for_pid(mach_task_self(),pid,&T)!=KERN_SUCCESS){printf("TFP_FAIL\n");return 1;}
    printf("klass=0x%llx  recherche de la chaîne...\n",(unsigned long long)klass);
    int solutions=0;
    for(uint64_t o1=0x40;o1<=0x180;o1+=8){
        uint64_t sf=r64(klass+o1); if(!ptr_ok(sf))continue;
        for(uint64_t o2=0;o2<=0x40;o2+=8){
            uint64_t wrap=r64(sf+o2); if(!ptr_ok(wrap))continue;
            for(uint64_t o3=0;o3<=0x40;o3+=8){
                uint64_t set=r64(wrap+o3); if(!ptr_ok(set))continue;
                // variantes count/array
                struct{uint64_t co,ao;} V[]={{0x18,0x10},{0x10,0x18},{0x18,0x20},{0x20,0x18},{0x1C,0x10}};
                for(auto&v:V){
                    uint32_t cnt=r32(set+v.co);
                    if(cnt==0||cnt>500)continue;
                    uint64_t arr=r64(set+v.ao); if(!ptr_ok(arr))continue;
                    int okobj=0,tested=0;
                    for(uint32_t j=0;j<cnt&&j<12;j++){
                        uint64_t el=r64(arr+0x20+8*j);
                        if(!ptr_ok(el))continue;
                        tested++;
                        if(r64(el)==klass&&worldvec(el,posoff))okobj++;
                    }
                    if(okobj>=3){
                        printf("  SOLUTION sf=klass+0x%llx (0x%llx) wrap=sf+0x%llx set=wrap+0x%llx "
                               "count@set+0x%llx(=%u) arr@set+0x%llx elements_ok=%d/%d\n",
                               (unsigned long long)o1,(unsigned long long)sf,(unsigned long long)o2,
                               (unsigned long long)o3,(unsigned long long)v.co,cnt,(unsigned long long)v.ao,okobj,tested);
                        solutions++;
                    }
                }
            }
        }
    }
    printf("total solutions: %d\n",solutions);
    return 0;
}
