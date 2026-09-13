// who — trouve tous les qwords égaux à une valeur donnée (toutes régions lisibles) + contexte
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
    uint64_t target=strtoull(argv[1],nullptr,16);
    int bytes=proc_listpids(PROC_ALL_PIDS,0,nullptr,0);
    std::vector<pid_t> ps(bytes/4+256);bytes=proc_listpids(PROC_ALL_PIDS,0,ps.data(),ps.size()*4);
    pid_t pid=0;for(int i=0;i<bytes/4;i++){char p[PROC_PIDPATHINFO_MAXSIZE]={};if(proc_pidpath(ps[i],p,sizeof p)>0&&strstr(p,"/RustClient.app/Contents/MacOS/Rust")){pid=ps[i];break;}}
    if(task_for_pid(mach_task_self(),pid,&T)!=KERN_SUCCESS){printf("TFP_FAIL\n");return 1;}
    printf("cible=0x%llx\n",(unsigned long long)target);
    mach_vm_address_t addr=0;mach_vm_size_t size=0;vm_region_basic_info_data_64_t info;mach_msg_type_number_t ic=VM_REGION_BASIC_INFO_COUNT_64;mach_port_t obj=0;
    const size_t CH=8*1024*1024;std::vector<uint8_t> buf(CH);int n=0;
    while(1){
        kern_return_t kr=mach_vm_region(T,&addr,&size,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&ic,&obj);
        if(kr!=KERN_SUCCESS)break;
        uint64_t cur=addr,left=size;addr+=size;int prot=info.protection;
        char pstr[8]="";if(prot&VM_PROT_READ)pstr[0]='r';if(prot&VM_PROT_WRITE)pstr[1]='w';if(prot&VM_PROT_EXECUTE)pstr[2]='x';
        while(left>0){size_t nn=(left<CH)?(size_t)left:CH;mach_vm_size_t got=0;
            if(mach_vm_read_overwrite(T,cur,nn,(mach_vm_address_t)buf.data(),&got)==KERN_SUCCESS)
                for(size_t i=0;i+8<=got;i+=8){
                    if(*(uint64_t*)(buf.data()+i)!=target)continue;
                    uint64_t at=cur+i;
                    printf("HIT 0x%llx (region %s)\n",(unsigned long long)at,pstr);
                    // contexte : 8 qwords avant, avec annotation chaîne
                    for(int k=8;k>=1;k--){
                        uint64_t a2=at-8*k;uint64_t v=r64(a2);char s[48]={};
                        if(v>0x1000000&&v<0x800000000000ULL&&str_at(v,s,40))printf("   -0x%02x 0x%llx = 0x%llx \"%s\"\n",8*k,(unsigned long long)a2,(unsigned long long)v,s);
                        else printf("   -0x%02x 0x%llx = 0x%llx\n",8*k,(unsigned long long)a2,(unsigned long long)v);
                    }
                    printf("   +00 0x%llx = cible\n",(unsigned long long)at);
                    for(int k=1;k<=4;k++){uint64_t a2=at+8*k;uint64_t v=r64(a2);char s[48]={};
                        if(v>0x1000000&&v<0x800000000000ULL&&str_at(v,s,40))printf("   +0x%02x 0x%llx = 0x%llx \"%s\"\n",8*k,(unsigned long long)a2,(unsigned long long)v,s);
                        else printf("   +0x%02x 0x%llx = 0x%llx\n",8*k,(unsigned long long)a2,(unsigned long long)v);}
                    n++;
                }
            if(left<=nn)break;cur+=nn;left-=nn;}
    }
    printf("total: %d\n",n);
    return 0;
}
