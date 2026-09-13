// RR02 radar v27 — chaîne validée v21 + retry permanent (ne quitte jamais)
// Sert de base stable : si le jeu est encore au menu/loading, il attend au lieu de mourir.
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <unistd.h>
#include <signal.h>
#include <fcntl.h>

static task_t g_task=MACH_PORT_NULL;
static uint64_t g_base=0;
static bool rd(uint64_t a,void*b,size_t n){mach_vm_size_t got=0;return mach_vm_read_overwrite(g_task,a,n,(mach_vm_address_t)b,&got)==KERN_SUCCESS&&got==n;}
static uint64_t r64(uint64_t a){uint64_t v=0;rd(a,&v,8);return v;}
struct Vec3{float x,y,z;};

static pid_t find_rust(){
    int bytes=proc_listpids(PROC_ALL_PIDS,0,nullptr,0);
    std::vector<pid_t> pids(bytes/sizeof(pid_t)+256);
    bytes=proc_listpids(PROC_ALL_PIDS,0,pids.data(),int(pids.size()*4));
    for(int i=0;i<bytes/4;i++){char p[PROC_PIDPATHINFO_MAXSIZE]={};if(proc_pidpath(pids[i],p,sizeof p)>0&&strstr(p,"/RustClient.app/Contents/MacOS/Rust"))return pids[i];}
    return 0;
}
static bool attach(){
    pid_t pid=find_rust();
    if(!pid){fprintf(stderr,"v27: attend RustClient...\n");return false;}
    if(g_task)g_task=MACH_PORT_NULL;
    if(task_for_pid(mach_task_self(),pid,&g_task)!=KERN_SUCCESS){fprintf(stderr,"v27: TFP_FAIL\n");return false;}
    task_dyld_info_data_t di={};mach_msg_type_number_t c=TASK_DYLD_INFO_COUNT;
    if(task_info(g_task,TASK_DYLD_INFO,(task_info_t)&di,&c)!=KERN_SUCCESS)return false;
    struct{uint32_t ver,cnt;uint64_t arr;}im={};
    if(!rd(di.all_image_info_addr,&im,sizeof im)||im.cnt>10000)return false;
    struct Img{uint64_t load,path,date;};
    Img* ims=new Img[im.cnt];
    bool ok=rd(im.arr,ims,im.cnt*sizeof(Img));
    if(ok){g_base=0;for(uint32_t i=0;i<im.cnt;i++){char p[512]={};if(rd(ims[i].path,p,512)&&strstr(p,"GameAssembly.dylib")){g_base=ims[i].load;break;}}}
    delete[] ims;
    if(g_base){fprintf(stderr,"v27: ATTACH pid=%d base=0x%llx\n",pid,(unsigned long long)g_base);return true;}
    return false;
}

int main(){
    while(!attach())usleep(2000000);
    FILE* out=nullptr;
    uint64_t klass=0,sf=0,wrapper=0,set=0,arr=0;uint32_t count=0;
    while(true){
        if(kill(find_rust(),0)!=0){fprintf(stderr,"v27: jeu mort -> re-attach\n");while(!attach())usleep(2000000);}
        klass=r64(g_base+0x897e148);
        sf=klass?r64(klass+0xB8):0;
        wrapper=sf?r64(sf+0x8):0;
        set=wrapper?r64(wrapper+0x10):0;
        count=0;if(set)rd(set+0x18,&count,4);
        arr=set?r64(set+0x10):0;
        if(!arr||count>200){fprintf(stderr,"v27: pool pas prêt klass=0x%llx sf=0x%llx cnt=%u\n",
            (unsigned long long)klass,(unsigned long long)sf,count);usleep(500000);continue;}
        if(!out)out=fopen("/tmp/rr02_radar.json","w");
        ftruncate(fileno(out),0);rewind(out);
        fprintf(out,"{\"local\":{\"x\":0,\"y\":0,\"z\":0},\"players\":[");
        bool first=true;int valid=0;
        for(uint32_t i=0;i<count;i++){
            uint64_t m=r64(arr+0x20+8*i);
            if(!m)continue;
            Vec3 p;rd(m+0x2F8,&p,12);
            if(!(p.x>-5000&&p.x<5000&&p.z>-5000&&p.z<5000&&p.y>-100&&p.y<1000))continue;
            if(p.x==0&&p.y==0&&p.z==0)continue;
            fprintf(out,"%s{\"x\":%.2f,\"y\":%.2f,\"z\":%.2f,\"local\":false,\"pm\":%llu}",
                    first?"":",",p.x,p.y,p.z,(unsigned long long)m);
            first=false;valid++;
        }
        fprintf(out,"]}\n");fflush(out);
        fprintf(stderr,"v27 tick: %d models\n",valid);
        usleep(100000);
    }
}
