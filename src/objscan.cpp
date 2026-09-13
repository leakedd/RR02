// objscan — trouve les objets liés à une classe donnée : signature de position (+0x2F8/+0x304)
// puis vérifie que l'en-tête (obj+0/8/0x10/0x18) ou sa cible contient le pointeur de classe.
// Usage: objscan <klass_hex> [posoff_hex]
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
static inline bool okv(const float*v){return std::isfinite(v[0])&&std::isfinite(v[1])&&std::isfinite(v[2])
    &&fabsf(v[0])<5000&&fabsf(v[2])<5000&&v[1]>0.5f&&v[1]<600.0f&&(fabsf(v[0])>3||fabsf(v[2])>3);}
int main(int argc,char**argv){
    uint64_t KL=strtoull(argv[1],nullptr,16);
    uint64_t posoff=argc>2?strtoull(argv[2],nullptr,16):0x2F8;
    int bytes=proc_listpids(PROC_ALL_PIDS,0,nullptr,0);
    std::vector<pid_t> ps(bytes/4+256);bytes=proc_listpids(PROC_ALL_PIDS,0,ps.data(),ps.size()*4);
    pid_t pid=0;for(int i=0;i<bytes/4;i++){char p[PROC_PIDPATHINFO_MAXSIZE]={};if(proc_pidpath(ps[i],p,sizeof p)>0&&strstr(p,"/RustClient.app/Contents/MacOS/Rust")){pid=ps[i];break;}}
    if(task_for_pid(mach_task_self(),pid,&T)!=KERN_SUCCESS){printf("TFP_FAIL\n");return 1;}
    printf("classe cible=0x%llx\n",(unsigned long long)KL);
    long long cand=0,matched=0;int shown=0;
    mach_vm_address_t addr=0;mach_vm_size_t size=0;vm_region_basic_info_data_64_t info;mach_msg_type_number_t ic=VM_REGION_BASIC_INFO_COUNT_64;mach_port_t obj=0;
    const size_t CH=8*1024*1024;std::vector<uint8_t> buf(CH+64);
    while(1){
        kern_return_t kr=mach_vm_region(T,&addr,&size,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&ic,&obj);
        if(kr!=KERN_SUCCESS)break;
        uint64_t cur=addr,left=size;addr+=size;
        if(!(info.protection&VM_PROT_WRITE)||size<1024*1024)continue;
        while(left>0){
            size_t n=(left<CH)?(size_t)left:CH;mach_vm_size_t got=0;
            if(mach_vm_read_overwrite(T,cur,n,(mach_vm_address_t)buf.data(),&got)==KERN_SUCCESS&&got>posoff+0x40){
                for(size_t i=posoff;i+0x18<=got;i+=8){
                    const float* f=(const float*)(buf.data()+i);
                    if(!okv(f))continue;
                    const float* f2=(const float*)(buf.data()+i+12);
                    if(!okv(f2))continue;
                    uint64_t o=cur+i-posoff;cand++;
                    const uint64_t*hdr=(const uint64_t*)(buf.data()+i-posoff);
                    const char* how=nullptr;
                    for(int k=0;k<4;k++){
                        uint64_t v=hdr[k];
                        if(v==KL){how="header";break;}
                        if(v>0x1000000&&v<0x800000000000ULL){
                            uint64_t t[8]={};if(rd(v,t,sizeof t))for(int j=0;j<8;j++)if(t[j]==KL){how="vtable/ptr+0x8*j";break;}
                        }
                        if(how)break;
                    }
                    if(!how)continue;
                    matched++;
                    if(shown<25){printf("  objet=0x%llx pos=(%.1f,%.1f,%.1f) via %s  hdr=[0x%llx 0x%llx 0x%llx 0x%llx]\n",
                        (unsigned long long)o,f[0],f[1],f[2],how,(unsigned long long)hdr[0],(unsigned long long)hdr[1],(unsigned long long)hdr[2],(unsigned long long)hdr[3]);shown++;}
                }
            }
            if(left<=n)break;cur+=n;left-=n;
        }
    }
    printf("candidats pos=%lld   objets liés à la classe=%lld\n",cand,matched);
    return 0;
}
