// hunt_pm — retrouve la classe PlayerModel SANS metadata : cherche les objets dont
// +0x2F8 contient un Vector3 « monde » plausible (|x|,|z| < 5000, |y| < 2000) et
// regroupe par pointeur de classe (objet+0x0). La classe dominante = PlayerModel.
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
static task_t T=MACH_PORT_NULL;static uint64_t BASE=0;
static bool rd(uint64_t a,void*b,size_t n){mach_vm_size_t g=0;return mach_vm_read_overwrite(T,a,n,(mach_vm_address_t)b,&g)==KERN_SUCCESS&&g==n;}
static uint64_t r64(uint64_t a){uint64_t v=0;rd(a,&v,8);return v;}
int main(int argc,char**argv){
    double posoff=argc>1?strtod(argv[1],nullptr):0x2F8;
    int bytes=proc_listpids(PROC_ALL_PIDS,0,nullptr,0);
    std::vector<pid_t> ps(bytes/4+256);bytes=proc_listpids(PROC_ALL_PIDS,0,ps.data(),ps.size()*4);
    pid_t pid=0;for(int i=0;i<bytes/4;i++){char p[PROC_PIDPATHINFO_MAXSIZE]={};if(proc_pidpath(ps[i],p,sizeof p)>0&&strstr(p,"/RustClient.app/Contents/MacOS/Rust")){pid=ps[i];break;}}
    if(task_for_pid(mach_task_self(),pid,&T)!=KERN_SUCCESS){printf("TFP_FAIL\n");return 1;}
    task_dyld_info_data_t di={};mach_msg_type_number_t c=TASK_DYLD_INFO_COUNT;
    task_info(T,TASK_DYLD_INFO,(task_info_t)&di,&c);
    struct{uint32_t ver,cnt;uint64_t arr;}im={};rd(di.all_image_info_addr,&im,sizeof im);
    struct I{uint64_t load,path,date;};std::vector<I> ims(im.cnt);rd(im.arr,ims.data(),im.cnt*sizeof(I));
    for(auto&i:ims){char p[512]={};if(i.load&&rd(i.path,p,512)&&strstr(p,"GameAssembly.dylib")){BASE=i.load;break;}}

    std::map<uint64_t,int> klassCount;
    std::map<uint64_t,std::vector<double>> klassSamples; // x,z samples
    long long ptrok=0, tested=0;
    mach_vm_address_t addr=0;mach_vm_size_t size=0;vm_region_basic_info_data_64_t info;mach_msg_type_number_t ic=VM_REGION_BASIC_INFO_COUNT_64;mach_port_t obj=0;
    const size_t CH=4*1024*1024;std::vector<uint8_t> buf(CH);
    while(1){
        kern_return_t kr=mach_vm_region(T,&addr,&size,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&ic,&obj);
        if(kr!=KERN_SUCCESS)break;
        mach_vm_address_t start=addr;addr+=size;
        if(!(info.protection&VM_PROT_WRITE))continue;      // heap seulement
        if(size<64*1024)continue;
        uint64_t cur=start,left=size;
        while(left>0){
            size_t n=(left<CH)?(size_t)left:CH;mach_vm_size_t got=0;
            if(mach_vm_read_overwrite(T,cur,n,(mach_vm_address_t)buf.data(),&got)==KERN_SUCCESS){
                for(size_t i=0;i+8<=got;i+=8){
                    uint64_t p=*(uint64_t*)(buf.data()+i);
                    if(p<0x1000000||p>0x800000000000ULL||(p&7))continue;
                    ptrok++;
                    float v[6]={};                       // 0x2F8 (pos) + 0x304 (suivant)
                    if(!rd(p+posoff,v,12))continue;
                    if(!(std::isfinite(v[0])&&std::isfinite(v[1])&&std::isfinite(v[2])))continue;
                    if(v[0]<=-5000||v[0]>=5000||v[2]<=-5000||v[2]>=5000||v[1]<=-200||v[1]>=1200)continue;
                    if(v[0]==0&&v[2]==0)continue;
                    tested++;
                    uint64_t kl=r64(p);
                    if(kl<0x1000000)continue;
                    klassCount[kl]++;
                    if(klassSamples[kl].size()<8){klassSamples[kl].push_back(v[0]);klassSamples[kl].push_back(v[2]);}
                }
            }
            if(left<=n)break;cur+=n;left-=n;
        }
    }
    std::vector<std::pair<int,uint64_t>> top;
    for(auto&kv:klassCount)top.push_back({kv.second,kv.first});
    std::sort(top.rbegin(),top.rend());
    printf("pointeurs testés=%lld  objets candidats=%lld  classes distinctes=%zu\n",ptrok,tested,klassCount.size());
    printf("--- top classes ---\n");
    for(size_t i=0;i<top.size()&&i<10;i++){
        uint64_t kl=top[i].second;
        printf("  klass=0x%llx  objets=%d  échantillons(x,z):",(unsigned long long)kl,top[i].first);
        auto&s=klassSamples[kl];
        for(size_t j=0;j+1<s.size();j++)printf(" (%.1f,%.1f)",s[j],s[j+1]);
        printf("\n");
    }
    return 0;
}
