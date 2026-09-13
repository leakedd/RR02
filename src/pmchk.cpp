// pmchk — inspecte une adresse : en-têtes de l'objet + Vector3 à +0x2F8/+0x304 + nom de la classe pointée
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
static bool str_at(uint64_t a,char*out,int max){uint8_t b[300]={};if(max>255)max=255;if(!rd(a,b,max))return false;int n=0;
  while(n<max-1&&b[n]>=32&&b[n]<=126){out[n]=(char)b[n];n++;}out[n]=0;return n>1;}
int main(int argc,char**argv){
    int bytes=proc_listpids(PROC_ALL_PIDS,0,nullptr,0);
    std::vector<pid_t> ps(bytes/4+256);bytes=proc_listpids(PROC_ALL_PIDS,0,ps.data(),ps.size()*4);
    pid_t pid=0;for(int i=0;i<bytes/4;i++){char p[PROC_PIDPATHINFO_MAXSIZE]={};if(proc_pidpath(ps[i],p,sizeof p)>0&&strstr(p,"/RustClient.app/Contents/MacOS/Rust")){pid=ps[i];break;}}
    if(task_for_pid(mach_task_self(),pid,&T)!=KERN_SUCCESS){printf("TFP_FAIL\n");return 1;}
    for(int a=1;a<argc;a++){
        uint64_t o=strtoull(argv[a],nullptr,16);
        printf("=== objet 0x%llx ===\n",(unsigned long long)o);
        char s[128]={};
        for(int k=0;k<4;k++){
            uint64_t v=r64(o+8*k);
            printf("  [%d] +0x%02x = 0x%llx",k,8*k,(unsigned long long)v);
            if(v>0x1000000&&v<0x800000000000ULL){
                // si c'est un klass : name à +0x20 ; si image : nom dll à +0
                char nm[128]={};char dll[128]={};uint64_t np=r64(v+0x20);
                if(np&&str_at(np,nm,100))printf("  (klass? name=\"%s\")",nm);
                else if(str_at(v,dll,100))printf("  (str=\"%s\")",dll);
                else{uint64_t i2=r64(v);char d2[128]={};if(i2&&str_at(i2,d2,100))printf("  (image=%s)",d2);}
            }
            printf("\n");
        }
        float pos[6]={};
        if(rd(o+0x2F8,pos,24))printf("  +0x2F8 (%.2f, %.2f, %.2f)   +0x304 (%.2f, %.2f, %.2f)\n",pos[0],pos[1],pos[2],pos[3],pos[4],pos[5]);
    }
    return 0;
}
