// hunt_pm2 — trouve les objets PlayerModel en lisant la position DANS le buffer (rapide).
// Signature : +0x2F8 ET +0x304 = deux Vector3 « monde » plausibles, précédés d'un classptr valide à obj+0x0.
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>
#include <map>
#include <cmath>
#include <algorithm>
static task_t T=MACH_PORT_NULL;
static bool rd(uint64_t a,void*b,size_t n){mach_vm_size_t g=0;return mach_vm_read_overwrite(T,a,n,(mach_vm_address_t)b,&g)==KERN_SUCCESS&&g==n;}
static uint64_t r64(uint64_t a){uint64_t v=0;rd(a,&v,8);return v;}
static inline bool okv(const float*v){return std::isfinite(v[0])&&std::isfinite(v[1])&&std::isfinite(v[2])
    &&fabsf(v[0])<5000&&fabsf(v[2])<5000&&v[1]>0.5f&&v[1]<600.0f&&(fabsf(v[0])>3||fabsf(v[2])>3);}
int main(int argc,char**argv){
    uint64_t posoff=argc>1?strtoull(argv[1],nullptr,16):0x2F8;
    int bytes=proc_listpids(PROC_ALL_PIDS,0,nullptr,0);
    std::vector<pid_t> ps(bytes/4+256);bytes=proc_listpids(PROC_ALL_PIDS,0,ps.data(),ps.size()*4);
    pid_t pid=0;for(int i=0;i<bytes/4;i++){char p[PROC_PIDPATHINFO_MAXSIZE]={};if(proc_pidpath(ps[i],p,sizeof p)>0&&strstr(p,"/RustClient.app/Contents/MacOS/Rust")){pid=ps[i];break;}}
    if(task_for_pid(mach_task_self(),pid,&T)!=KERN_SUCCESS){printf("TFP_FAIL\n");return 1;}
    std::map<uint64_t,int> kc; std::map<uint64_t,std::vector<std::pair<double,double>>> ks;
    long long cand=0;
    mach_vm_address_t addr=0;mach_vm_size_t size=0;vm_region_basic_info_data_64_t info;mach_msg_type_number_t ic=VM_REGION_BASIC_INFO_COUNT_64;mach_port_t obj=0;
    const size_t CH=8*1024*1024;std::vector<uint8_t> buf(CH+64);
    while(1){
        kern_return_t kr=mach_vm_region(T,&addr,&size,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&ic,&obj);
        if(kr!=KERN_SUCCESS)break;
        mach_vm_address_t start=addr;addr+=size;
        if(!(info.protection&VM_PROT_WRITE)||size<1024*1024)continue;
        uint64_t cur=start,left=size;
        while(left>0){
            size_t n=(left<CH)?(size_t)left:CH;mach_vm_size_t got=0;
            if(mach_vm_read_overwrite(T,cur,n,(mach_vm_address_t)buf.data(),&got)==KERN_SUCCESS&&got>posoff+0x40){
                for(size_t i=posoff;i+0x18<=got;i+=8){
                    const float* f=(const float*)(buf.data()+i);
                    if(!okv(f))continue;
                    const float* f2=(const float*)(buf.data()+i+12);
                    if(!okv(f2))continue;                       // second Vector3 interne
                    uint64_t objp=cur+i-posoff;
                    uint64_t kl=*(uint64_t*)(buf.data()+i-posoff);
                    if(kl<0x1000000||kl>0x800000000000ULL||(kl&7))continue;
                    cand++;kc[kl]++;
                    auto&s=ks[kl];if(s.size()<10)s.push_back({f[0],f[2]});
                }
            }
            if(left<=n)break;cur+=n;left-=n;
        }
    }
    std::vector<std::pair<int,uint64_t>> top;
    for(auto&kv:kc)top.push_back({kv.second,kv.first});
    std::sort(top.rbegin(),top.rend());
    printf("candidats=%lld  classes=%zu\n",cand,kc.size());
    for(size_t i=0;i<top.size()&&i<12;i++){
        uint64_t kl=top[i].second;
        printf("klass=0x%llx n=%d  ex:",(unsigned long long)kl,top[i].first);
        for(auto&p:ks[kl])printf(" (%.1f,%.1f)",p.first,p.second);
        printf("\n");
    }
    return 0;
}
