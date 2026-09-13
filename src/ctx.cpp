// ctx — pour chaque occurrence d'une chaîne ASCII, imprime le contexte (12 qwords avant, 4 après)
// avec décodage : tout qword pointant vers une chaîne lisible est annoté. Sert à retrouver le layout Il2CppClass.
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>
static task_t T=MACH_PORT_NULL;
static bool rd(uint64_t a,void*b,size_t n){mach_vm_size_t g=0;return mach_vm_read_overwrite(T,a,n,(mach_vm_address_t)b,&g)==KERN_SUCCESS&&g==n;}
static bool str_at(uint64_t a,char*out,int max){uint8_t b[300]={};if(max>255)max=255;if(!rd(a,b,max))return false;int n=0;
  while(n<max-1&&b[n]>=32&&b[n]<=126){out[n]=(char)b[n];n++;}out[n]=0;return n>1;}
int main(int argc,char**argv){
    const char* want=argv[1];size_t L=strlen(want);
    int bytes=proc_listpids(PROC_ALL_PIDS,0,nullptr,0);
    std::vector<pid_t> ps(bytes/4+256);bytes=proc_listpids(PROC_ALL_PIDS,0,ps.data(),ps.size()*4);
    pid_t pid=0;for(int i=0;i<bytes/4;i++){char p[PROC_PIDPATHINFO_MAXSIZE]={};if(proc_pidpath(ps[i],p,sizeof p)>0&&strstr(p,"/RustClient.app/Contents/MacOS/Rust")){pid=ps[i];break;}}
    if(task_for_pid(mach_task_self(),pid,&T)!=KERN_SUCCESS){printf("TFP_FAIL\n");return 1;}
    std::vector<uint64_t> hits;
    mach_vm_address_t addr=0;mach_vm_size_t size=0;vm_region_basic_info_data_64_t info;mach_msg_type_number_t ic=VM_REGION_BASIC_INFO_COUNT_64;mach_port_t obj=0;
    const size_t CH=4*1024*1024;std::vector<uint8_t> buf(CH+64);
    while(1){
        kern_return_t kr=mach_vm_region(T,&addr,&size,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&ic,&obj);
        if(kr!=KERN_SUCCESS)break;
        uint64_t cur=addr,left=size;addr+=size;
        while(left>0){size_t n=(left<CH)?(size_t)left:CH;mach_vm_size_t got=0;
            if(mach_vm_read_overwrite(T,cur,n,(mach_vm_address_t)buf.data(),&got)==KERN_SUCCESS)
                for(size_t i=0;i+L+1<=got;i++){
                    if(buf[i]!=(uint8_t)want[0])continue;
                    if(!memcmp(buf.data()+i,want,L)&&buf[i+L]==0)hits.push_back(cur+i);
                }
            if(left<=n)break;cur+=n;left-=n;}
    }
    printf("occurrences exactes de '%s\\0': %zu\n",want,hits.size());
    for(size_t h=0;h<hits.size();h++){
        uint64_t A=hits[h];
        printf("\n=== #%zu @ 0x%llx ===\n",h,(unsigned long long)A);
        uint64_t base=A-0x60;
        uint8_t raw[0x80+0x30]={};if(!rd(base,raw,sizeof raw)){printf("  (contexte illisible)\n");continue;}
        for(int k=0;k<0x60/8;k++){
            uint64_t v=*(uint64_t*)(raw+8*k);
            char s[64]={};const char* an="";
            if(v>0x1000000&&v<0x800000000000ULL&&str_at(v,s,48)){static char tmp[80];snprintf(tmp,sizeof tmp," -> \"%s\"",s);an=tmp;}
            printf("  [%+.3d] 0x%llx = 0x%llx%s\n",-(0x60-8*k),(unsigned long long)(base+8*k),(unsigned long long)v,an);
        }
        printf("  [  0] 0x%llx = \"%s\"  <-- occurrence\n",(unsigned long long)A,want);
    }
    return 0;
}
