// RR02 radar v25 — v21 + auto-reconnect au reboot du jeu
// Boucle externe : si RustClient meurt, re-cherche le PID + task_for_pid + base, indefinitely.
// Chaîne: base+[0x8d402f0] -> klass -> +0xB8 static_fields -> +0x8 wrapper(046885<T>)
//         -> +0x10 ListHashSet -> +0x18 count, +0x10 array -> +0x20+8i = PlayerModel*
//         PlayerModel +0x2F8 = Vector3 position
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>

static task_t g_task=MACH_PORT_NULL;
static uint64_t g_base=0;
static pid_t g_pid=0;
static bool rd(uint64_t a,void*b,size_t n){mach_vm_size_t got=0;return mach_vm_read_overwrite(g_task,a,n,(mach_vm_address_t)b,&got)==KERN_SUCCESS&&got==n;}
static uint64_t r64(uint64_t a){uint64_t v=0;rd(a,&v,8);return v;}
struct Vec3{float x,y,z;};
struct Img{uint64_t load,path,date;};

static pid_t find_rust(){
    int bytes=proc_listpids(PROC_ALL_PIDS,0,nullptr,0);
    std::vector<pid_t> pids(bytes/sizeof(pid_t)+256);
    bytes=proc_listpids(PROC_ALL_PIDS,0,pids.data(),int(pids.size()*4));
    for(int i=0;i<bytes/4;i++){char p[PROC_PIDPATHINFO_MAXSIZE]={};if(proc_pidpath(pids[i],p,sizeof p)>0&&strstr(p,"/RustClient.app/Contents/MacOS/Rust"))return pids[i];}
    return 0;
}

static bool attach(){
    g_pid=find_rust();
    if(!g_pid){fprintf(stderr,"v25: attend RustClient...\n");return false;}
    if(g_task!=MACH_PORT_NULL)mach_port_deallocate(mach_task_self(),g_task);
    g_task=MACH_PORT_NULL;
    if(task_for_pid(mach_task_self(),g_pid,&g_task)!=KERN_SUCCESS){fprintf(stderr,"v25: TFP_FAIL pid=%d\n",g_pid);return false;}
    task_dyld_info_data_t di={};mach_msg_type_number_t c=TASK_DYLD_INFO_COUNT;
    if(task_info(g_task,TASK_DYLD_INFO,(task_info_t)&di,&c)!=KERN_SUCCESS)return false;
    struct{uint32_t ver,cnt;uint64_t arr;}im={};
    if(!rd(di.all_image_info_addr,&im,sizeof im)||im.cnt>10000)return false;
    Img* ims=new Img[im.cnt];
    bool ok=rd(im.arr,ims,im.cnt*sizeof *ims);
    if(ok){g_base=0;for(uint32_t i=0;i<im.cnt;i++){char p[512]={};if(rd(ims[i].path,p,512)&&strstr(p,"GameAssembly.dylib")){g_base=ims[i].load;break;}}}
    delete[] ims;
    if(g_base){fprintf(stderr,"v25: ATTACHED pid=%d base=0x%llx\n",g_pid,(unsigned long long)g_base);return true;}
    return false;
}

int main(){
    if(!attach()){ // premier essai immédiat
        while(!attach())usleep(2000000); // re-essaie toutes les 2s, pour toujours
    }
    FILE* out=nullptr;
    while(true){
        // santé du jeu : si le PID est parti → re-attach
        if(kill(g_pid,0)!=0){fprintf(stderr,"v25: jeu mort, pause/re-attach\n");g_base=0;
            while(!attach())usleep(2000000);}
        if(!g_base){usleep(200000);continue;}

        uint64_t klass=r64(g_base+0x8d402f0);
        if(!klass){usleep(200000);continue;}
        uint64_t sf=r64(klass+0xB8);
        uint64_t wrapper=r64(sf+0x8);
        uint64_t set=r64(wrapper+0x10);
        uint32_t count=0;rd(set+0x18,&count,4);
        uint64_t arr=r64(set+0x10);
        if(!arr||count>200){usleep(200000);continue;}
        if(!out)out=fopen("/tmp/rr02_radar.json","w");
        ftruncate(fileno(out),0);
        rewind(out);
        fprintf(out,"{\"local\":{\"x\":0,\"y\":0,\"z\":0},\"players\":[");
        bool first=true;int valid=0;
        for(uint32_t i=0;i<count;i++){
            uint64_t m=r64(arr+0x20+8*i);
            if(!m)continue;
            Vec3 p;rd(m+0x2F8,&p,12);
            uint8_t local=false;rd(m+0x375,&local,1);
            if(!(p.x>-5000&&p.x<5000&&p.z>-5000&&p.z<5000&&p.y>-100&&p.y<1000))continue;
            if(p.x==0&&p.y==0&&p.z==0)continue;
            fprintf(out,"%s{\"x\":%.2f,\"y\":%.2f,\"z\":%.2f,\"local\":%s}",
                    first?"":",",p.x,p.y,p.z,local?"true":"false");
            first=false;valid++;
        }
        fprintf(out,"]}\n");
        fflush(out);
        fprintf(stderr,"tick: %d players\n",valid);
        usleep(100000);
    }
}
