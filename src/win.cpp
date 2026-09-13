// win — cherche une chaîne ASCII dans une fenêtre autour d'une adresse (calage de struct)
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>
#include <algorithm>
static task_t T=MACH_PORT_NULL;
static bool rd(uint64_t a,void*b,size_t n){mach_vm_size_t g=0;return mach_vm_read_overwrite(T,a,n,(mach_vm_address_t)b,&g)==KERN_SUCCESS&&g==n;}
int main(int argc,char**argv){
    int bytes=proc_listpids(PROC_ALL_PIDS,0,nullptr,0);
    std::vector<pid_t> ps(bytes/4+256);bytes=proc_listpids(PROC_ALL_PIDS,0,ps.data(),ps.size()*4);
    pid_t pid=0;for(int i=0;i<bytes/4;i++){char p[PROC_PIDPATHINFO_MAXSIZE]={};if(proc_pidpath(ps[i],p,sizeof p)>0&&strstr(p,"/RustClient.app/Contents/MacOS/Rust")){pid=ps[i];break;}}
    if(task_for_pid(mach_task_self(),pid,&T)!=KERN_SUCCESS){printf("TFP_FAIL\n");return 1;}
    uint64_t a=strtoull(argv[1],nullptr,16);size_t win=argc>3?strtoul(argv[3],nullptr,0):0x400;
    const char* want=argv[2];size_t L=strlen(want);
    std::vector<uint8_t> b(win*2+64);
    if(!rd(a-win,b.data(),b.size())){printf("READ_FAIL\n");return 1;}
    int n=0;
    for(size_t i=0;i+L<=b.size();i++){
        if(b[i]!=want[0])continue;
        if(!memcmp(b.data()+i,want,L)){
            long long off=(long long)i-(long long)win;
            printf("  +0x%llx -> \"%s\" (adresse 0x%llx)\n",off,want,(unsigned long long)(a+off));
            n++;
        }
    }
    printf("occurrences dans [a-0x%zx, a+0x%zx]: %d\n",win,win,n);
    return 0;
}
