// peek — hexdump d'une adresse + suivi des pointeurs (pour cartographier Il2CppClass en v39)
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#include <cstdio>
#include <cstring>
#include <vector>
#include <cstdint>
static task_t T=MACH_PORT_NULL;
static bool rd(uint64_t a,void*b,size_t n){mach_vm_size_t g=0;return mach_vm_read_overwrite(T,a,n,(mach_vm_address_t)b,&g)==KERN_SUCCESS&&g==n;}
static bool ascii(uint64_t a,char*out,int max){uint8_t b[256]={};if(!rd(a,b,std::min(255,max)))return false;int n=0;
  while(n<max-1&&b[n]>=32&&b[n]<=126){out[n]=(char)b[n];n++;}out[n]=0;return n>1;}
int main(int argc,char**argv){
    int bytes=proc_listpids(PROC_ALL_PIDS,0,nullptr,0);
    std::vector<pid_t> ps(bytes/4+256);bytes=proc_listpids(PROC_ALL_PIDS,0,ps.data(),ps.size()*4);
    pid_t pid=0;for(int i=0;i<bytes/4;i++){char p[PROC_PIDPATHINFO_MAXSIZE]={};if(proc_pidpath(ps[i],p,sizeof p)>0&&strstr(p,"/RustClient.app/Contents/MacOS/Rust")){pid=ps[i];break;}}
    if(task_for_pid(mach_task_self(),pid,&T)!=KERN_SUCCESS){printf("TFP_FAIL\n");return 1;}
    uint64_t a=strtoull(argv[1],nullptr,16);size_t n=argc>2?strtoul(argv[2],nullptr,0):256;
    std::vector<uint8_t> b(n);if(!rd(a,b.data(),n)){printf("READ_FAIL\n");return 1;}
    for(size_t i=0;i<n;i+=16){
        printf("%012llx  ",(unsigned long long)(a+i));
        for(size_t j=0;j<16&&i+j<n;j++)printf("%02x ",b[i+j]);
        printf(" |");
        for(size_t j=0;j<16&&i+j<n;j++){uint8_t c=b[i+j];printf("%c",(c>=32&&c<127)?c:'.');}
        printf("|\n");
    }
    printf("--- pointeurs ---\n");
    for(size_t i=0;i+8<=n;i+=8){
        uint64_t v=*(uint64_t*)(b.data()+i);
        if(v<0x1000000||v>0x800000000000ULL)continue;
        char s[128]={};
        if(ascii(v,s,120))printf("  +0x%02zx -> 0x%llx \"%s\"\n",i,(unsigned long long)v,s);
    }
    return 0;
}
