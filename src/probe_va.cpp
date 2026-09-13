// probe_va — vérifie base + slots TypeInfo + nom de klass
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#include <cstdio>
#include <cstring>
#include <vector>
#include <cstdint>
static task_t T=MACH_PORT_NULL;static uint64_t BASE=0;
static bool rd(uint64_t a,void*b,size_t n){mach_vm_size_t g=0;return mach_vm_read_overwrite(T,a,n,(mach_vm_address_t)b,&g)==KERN_SUCCESS&&g==n;}
static uint64_t r64(uint64_t a){uint64_t v=0;rd(a,&v,8);return v;}
int main(){
    int bytes=proc_listpids(PROC_ALL_PIDS,0,nullptr,0);
    std::vector<pid_t> ps(bytes/4+256);bytes=proc_listpids(PROC_ALL_PIDS,0,ps.data(),ps.size()*4);
    pid_t pid=0;for(int i=0;i<bytes/4;i++){char p[PROC_PIDPATHINFO_MAXSIZE]={};if(proc_pidpath(ps[i],p,sizeof p)>0&&strstr(p,"/RustClient.app/Contents/MacOS/Rust")){pid=ps[i];break;}}
    printf("pid=%d\n",pid);
    if(task_for_pid(mach_task_self(),pid,&T)!=KERN_SUCCESS){printf("TFP_FAIL\n");return 1;}
    task_dyld_info_data_t di={};mach_msg_type_number_t c=TASK_DYLD_INFO_COUNT;
    task_info(T,TASK_DYLD_INFO,(task_info_t)&di,&c);
    struct{uint32_t ver,cnt;uint64_t arr;}im={};rd(di.all_image_info_addr,&im,sizeof im);
    struct Img{uint64_t load,path,date;};std::vector<Img> ims(im.cnt);rd(im.arr,ims.data(),im.cnt*sizeof(Img));
    for(auto&i:ims){char p[512]={};if(i.load&&rd(i.path,p,512)&&strstr(p,"GameAssembly.dylib")){BASE=i.load;printf("image=%s\n",p+ (strlen(p)>60?strlen(p)-60:0));break;}}
    uint32_t magic=0;rd(BASE,&magic,4);printf("BASE=0x%llx magic=0x%08x (attendu feedfacf)\n",(unsigned long long)BASE,magic);
    uint64_t slots[]={0x897e148ULL,0x8987108ULL,0x89879f0ULL};
    for(uint64_t s:slots){
        uint64_t v=r64(BASE+s);
        char nm[128]={0};bool ok=rd(v+0x10,nm,100);
        uint64_t sf=r64(v+0xB8);
        printf("slot+0x%llx = 0x%llx  name@+0x10='%s' sf(+0xB8)=0x%llx\n",(unsigned long long)s,(unsigned long long)v,ok?nm:"<unreadable>",(unsigned long long)sf);
    }
    // PlayerModel : essaie l'ancien + le nouveau
    return 0;
}
