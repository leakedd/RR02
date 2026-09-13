// klassfind — retrouve toutes les Il2CppClass par leur auto-référence : r64(X+0x78) == X
// puis lit name@+0x10 / namespaze@+0x18 / image@+0x00 / static_fields@+0xB8 (layout v39 confirmé par il2cpp.h)
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>
static task_t T=MACH_PORT_NULL;
static bool rd(uint64_t a,void*b,size_t n){mach_vm_size_t g=0;return mach_vm_read_overwrite(T,a,n,(mach_vm_address_t)b,&g)==KERN_SUCCESS&&g==n;}
static uint64_t r64(uint64_t a){uint64_t v=0;rd(a,&v,8);return v;}
static bool str_at(uint64_t a,char*out,int max){uint8_t b[300]={};if(max>255)max=255;if(!rd(a,b,max))return false;int n=0;
  while(n<max-1&&b[n]>=32&&b[n]<=126){out[n]=(char)b[n];n++;}out[n]=0;return n>0;}
int main(int argc,char**argv){
    const char* want=argc>1?argv[1]:nullptr;   // optionnel : filtrer sur un nom
    int bytes=proc_listpids(PROC_ALL_PIDS,0,nullptr,0);
    std::vector<pid_t> ps(bytes/4+256);bytes=proc_listpids(PROC_ALL_PIDS,0,ps.data(),ps.size()*4);
    pid_t pid=0;for(int i=0;i<bytes/4;i++){char p[PROC_PIDPATHINFO_MAXSIZE]={};if(proc_pidpath(ps[i],p,sizeof p)>0&&strstr(p,"/RustClient.app/Contents/MacOS/Rust")){pid=ps[i];break;}}
    if(task_for_pid(mach_task_self(),pid,&T)!=KERN_SUCCESS){printf("TFP_FAIL\n");return 1;}
    long long found=0;
    mach_vm_address_t addr=0;mach_vm_size_t size=0;vm_region_basic_info_data_64_t info;mach_msg_type_number_t ic=VM_REGION_BASIC_INFO_COUNT_64;mach_port_t obj=0;
    const size_t CH=8*1024*1024;std::vector<uint8_t> buf(CH+1024);
    while(1){
        kern_return_t kr=mach_vm_region(T,&addr,&size,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&ic,&obj);
        if(kr!=KERN_SUCCESS)break;
        uint64_t cur=addr,left=size;addr+=size;
        if(!(info.protection&VM_PROT_WRITE)||size<4096)continue;
        while(left>0){
            size_t n=(left<CH)?(size_t)left:CH;mach_vm_size_t got=0;
            if(mach_vm_read_overwrite(T,cur,n,(mach_vm_address_t)buf.data(),&got)==KERN_SUCCESS&&got>0x180){
                for(size_t o=0;o+0x180<=got;o+=8){
                    uint64_t X=cur+o;
                    if(*(uint64_t*)(buf.data()+o+0x78)!=X)continue;
                    uint64_t namep=*(uint64_t*)(buf.data()+o+0x10);
                    char nm[128]={},ns[128]={};
                    if(!(namep>0x1000000&&str_at(namep,nm,100)))continue;
                    if(want&&strcmp(nm,want))continue;
                    uint64_t nsp=*(uint64_t*)(buf.data()+o+0x18);
                    if(!(nsp>0x1000000&&str_at(nsp,ns,100)))ns[0]=0;
                    uint64_t img=*(uint64_t*)(buf.data()+o+0x00);
                    uint64_t sf=*(uint64_t*)(buf.data()+o+0xB8);
                    uint32_t instsz=0,sfisz=0;rd(X+0xF8,&instsz,4);rd(X+0x108,&sfisz,4);
                    printf("KLASS 0x%llx ns='%s' name='%s' image=0x%llx static_fields=0x%llx inst_size=0x%x sf_size=0x%x\n",
                        (unsigned long long)X,ns,nm,(unsigned long long)img,(unsigned long long)sf,instsz,sfisz);
                    fflush(stdout);found++;
                }
            }
            if(left<=n)break;cur+=n;left-=n;
        }
    }
    printf("total klasses: %lld\n",found);
    return 0;
}
