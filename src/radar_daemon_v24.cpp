// RR02 radar v24 — Local player via List<BasePlayer> sf+0x28 (chaîne GetLocalPlayer désassemblée)
// Chaîne: base+[0x8d48400] -> klass %b53757d1 -> +0xB8 sf -> [sf+0x28] = 046885<T> wrapper
//         -> +0x10 set(ListHashSet) -> +0x18 count, +0x10 array -> +0x20+8i = BasePlayer*
// BasePlayer: +0x398/+0x399 = bools publics candidats local, +0x3F8 = PlayerModel
// Print de diagnostic pour chaque bp. JSON /tmp/rr02_radar.json.
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <unistd.h>
#include <fcntl.h>

static task_t g_task=MACH_PORT_NULL;
static uint64_t g_base=0;
static bool rd(uint64_t a,void*b,size_t n){mach_vm_size_t got=0;return mach_vm_read_overwrite(g_task,a,n,(mach_vm_address_t)b,&got)==KERN_SUCCESS&&got==n;}
static uint64_t r64(uint64_t a){uint64_t v=0;rd(a,&v,8);return v;}
static bool dbg_once=false;
struct Vec3{float x,y,z;};

int main(){
    pid_t pid=0;int bytes=proc_listpids(PROC_ALL_PIDS,0,nullptr,0);
    std::vector<pid_t> pids(bytes/sizeof(pid_t)+256);
    bytes=proc_listpids(PROC_ALL_PIDS,0,pids.data(),int(pids.size()*4));
    for(int i=0;i<bytes/4;i++){char p[PROC_PIDPATHINFO_MAXSIZE]={};if(proc_pidpath(pids[i],p,sizeof p)>0&&strstr(p,"/RustClient.app/Contents/MacOS/Rust")){pid=pids[i];break;}}
    if(!pid){fprintf(stderr,"NO_RUST\n");return 1;}
    if(task_for_pid(mach_task_self(),pid,&g_task)!=KERN_SUCCESS){fprintf(stderr,"TFP_FAIL\n");return 1;}

    task_dyld_info_data_t di={};mach_msg_type_number_t c=TASK_DYLD_INFO_COUNT;
    if(task_info(g_task,TASK_DYLD_INFO,(task_info_t)&di,&c)!=KERN_SUCCESS)return 2;
    struct{uint32_t ver,cnt;uint64_t arr;}im={};
    if(!rd(di.all_image_info_addr,&im,sizeof im)||im.cnt>10000)return 3;
    struct Img{uint64_t load,path,date;};
    Img* ims=new Img[im.cnt];
    if(!rd(im.arr,ims,im.cnt*sizeof *ims))return 4;
    for(uint32_t i=0;i<im.cnt;i++){char p[512]={};if(rd(ims[i].path,p,512)&&strstr(p,"GameAssembly.dylib")){g_base=ims[i].load;break;}}
    delete[] ims;
    if(!g_base)return 5;

    FILE* out=nullptr;
    while(true){
        uint64_t klass=r64(g_base+0x8d48400);
        if(!klass){usleep(200000);continue;}
        if(!dbg_once){ // appel unique : dump chaîne
            uint64_t sfdbg=r64(r64(g_base+0x8d48400)+0xB8);
            fprintf(stderr,"v24dbg: klass=%llx sf=%llx sf[0x28]=%llx\n",(unsigned long long)r64(g_base+0x8d48400),(unsigned long long)sfdbg,(unsigned long long)r64(sfdbg+0x28));
            dbg_once=true;
        }
        uint64_t sf=r64(klass+0xB8);if(!sf){usleep(200000);continue;}
        uint64_t wrap=r64(sf+0x28);if(!wrap){usleep(200000);continue;}
        uint64_t set=r64(wrap+0x10);if(!set){usleep(200000);continue;}
        uint32_t count=0;rd(set+0x18,&count,4);
        uint64_t arr=r64(set+0x10);
        if(!arr||count>500){usleep(200000);continue;}
        if(!out)out=fopen("/tmp/rr02_radar.json","w");
        ftruncate(fileno(out),0);
        rewind(out);
        fprintf(out,"{\"local\":{\"x\":0,\"y\":0,\"z\":0},\"players\":[");
        bool first=true;int valid=0;
        for(uint32_t i=0;i<count;i++){
            uint64_t bp=r64(arr+0x20+8*i);if(!bp)continue;
            uint8_t b398=0,b399=0;rd(bp+0x398,&b398,1);rd(bp+0x399,&b399,1);
            uint64_t pm=r64(bp+0x3F8);if(!pm)continue;
            Vec3 p;rd(pm+0x2F8,&p,12);
            if(!(p.x>-5000&&p.x<5000&&p.z>-5000&&p.z<5000&&p.y>-100&&p.y<1000))continue;
            if(p.x==0&&p.y==0&&p.z==0)continue;
            fprintf(stdout,"bp=%p pm=%p b398=%d b399=%d pos=(%.1f,%.1f,%.1f)\n",
                    (void*)bp,(void*)pm,b398,b399,p.x,p.y,p.z);
            fprintf(out,"%s{\"x\":%.2f,\"y\":%.2f,\"z\":%.2f,\"local\":%s}",
                    first?"":",",p.x,p.y,p.z,(b398||b399)?"true":"false");
            first=false;valid++;
        }
        fprintf(out,"]}\n");fflush(out);fflush(stdout);
        fprintf(stderr,"v24 tick: %d\n",valid);
        usleep(100000);
    }
}
