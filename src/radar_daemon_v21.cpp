// RR02 radar v21 — Liste joueurs via ListComponent<PlayerModel> (chaîne validée live)
// Chaîne: base+[0x8d402f0] -> klass -> +0xB8 static_fields -> +0x8 wrapper(046885<T>)
//         -> +0x10 ListHashSet(2d6740) -> +0x18 count, +0x10 array -> elements +0x20
//         PlayerModel pos = +0x2F8 (Vector3)
// Local detection: v22 — dump bools 0x374/0x375/0x37C/0x37D dans stderr pour identifier le flag
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <unistd.h>
#include <fcntl.h>
#include <cstdio>

static task_t g_task=MACH_PORT_NULL;
static uint64_t g_base=0;
static bool rd(uint64_t a,void*b,size_t n){mach_vm_size_t got=0;return mach_vm_read_overwrite(g_task,a,n,(mach_vm_address_t)b,&got)==KERN_SUCCESS&&got==n;}
static uint64_t r64(uint64_t a){uint64_t v=0;rd(a,&v,8);return v;}

struct Vec3{float x,y,z;};

int main(){
    // PID RustClient
    pid_t pid=0;int bytes=proc_listpids(PROC_ALL_PIDS,0,nullptr,0);
    std::vector<pid_t> pids(bytes/sizeof(pid_t)+256);
    bytes=proc_listpids(PROC_ALL_PIDS,0,pids.data(),int(pids.size()*4));
    for(int i=0;i<bytes/4;i++){char p[PROC_PIDPATHINFO_MAXSIZE]={};if(proc_pidpath(pids[i],p,sizeof p)>0&&strstr(p,"/RustClient.app/Contents/MacOS/Rust")){pid=pids[i];break;}}
    if(!pid){fprintf(stderr,"NO_RUST\n");return 1;}
    if(task_for_pid(mach_task_self(),pid,&g_task)!=KERN_SUCCESS){fprintf(stderr,"TFP_FAIL\n");return 1;}

    // Base via dyld_info
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

        uint64_t klass=r64(g_base+0x8d402f0);
        if(!klass){usleep(200000);continue;}
        sf=r64(klass+0xB8);
        wrapper=r64(sf+0x8);
        set=r64(wrapper+0x10);
        count=0;rd(set+0x18,&count,4);
        arr=r64(set+0x10);
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
    fprintf(stderr,"base=0x%llx klass=0x%llx sf=0x%llx wrap=0x%llx set=0x%llx count=%u arr=0x%llx\n",
            (unsigned long long)g_base,(unsigned long long)klass,(unsigned long long)sf,
            (unsigned long long)wrapper,(unsigned long long)set,count,(unsigned long long)arr);
    if(!arr||count>200){fprintf(stderr,"BAD_SET\n");return 7;}

    // Boucle temps réel 10Hz
    FILE* out=nullptr;
    while(true){
        klass=r64(g_base+0x8d402f0);
        if(!klass){usleep(200000);continue;}
        sf=r64(klass+0xB8);
        wrapper=r64(sf+0x8);
        set=r64(wrapper+0x10);
        count=0;rd(set+0x18,&count,4);
        arr=r64(set+0x10);
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
            // [debug] dump bools internes autour de 0x374..0x392 pour identifier le local
            uint8_t dbg[16]={0};rd(m+0x374,dbg,16);
            fprintf(stderr,"    player %d bools[0x374..]=%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,%d\n",
                    i,dbg[0],dbg[1],dbg[2],dbg[3],dbg[4],dbg[5],dbg[6],dbg[7],dbg[8],dbg[9],dbg[10],dbg[11],dbg[12],dbg[13],dbg[14],dbg[15]);

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
