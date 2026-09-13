
// RR02 radar v23 — Local player via sf+0x28 List<BasePlayer> (chaîne %b53757d1 validée par désassemblage)
// Local = le BasePlayer dont les bools publics 0x398/0x399 diffèrent, ou celui dont on mesure que la pos bouge
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <unistd.h>
static task_t T;static uint64_t B;
static bool rd(uint64_t a,void*b,size_t n){mach_vm_size_t g=0;return mach_vm_read_overwrite(T,a,n,(mach_vm_address_t)b,&g)==KERN_SUCCESS&&g==n;}
static uint64_t r64(uint64_t a){uint64_t v=0;rd(a,&v,8);return v;}
struct V3{float x,y,z;};
int main(){
    pid_t pid=0;int nb=proc_listpids(PROC_ALL_PIDS,0,nullptr,0);std::vector<pid_t> ps(nb/4+256);
    nb=proc_listpids(PROC_ALL_PIDS,0,ps.data(),ps.size()*4);
    for(int i=0;i<nb/4;i++){char p[PROC_PIDPATHINFO_MAXSIZE]={};if(proc_pidpath(ps[i],p,sizeof p)>0&&strstr(p,"/RustClient.app/Contents/MacOS/Rust")){pid=ps[i];break;}}
    if(!pid)return 1;
    if(task_for_pid(mach_task_self(),pid,&T)!=KERN_SUCCESS)return 2;
    task_dyld_info_data_t di={};mach_msg_type_number_t c=TASK_DYLD_INFO_COUNT;
    if(task_info(T,TASK_DYLD_INFO,(task_info_t)&di,&c)!=KERN_SUCCESS)return 3;
    struct{uint32_t ver,cnt;uint64_t arr;}im={};
    if(!rd(di.all_image_info_addr,&im,sizeof im))return 4;
    struct Img{uint64_t load,path,date;};Img* s=new Img[im.cnt];
    if(!rd(im.arr,s,im.cnt*sizeof (Img)))return 5;
    for(uint32_t i=0;i<im.cnt;i++){char p[512]={};if(rd(s[i].path,p,512)&&strstr(p,"GameAssembly.dylib")){B=s[i].load;break;}}
    delete[] s;
    if(!B)return 6;

    FILE* out=nullptr;
    while(true){
        uint64_t klass=r64(B+0x8d48400);    // %b53757d1 TypeInfo
        if(!klass){usleep(200000);continue;}
        uint64_t sf=r64(klass+0xB8);if(!sf){usleep(200000);continue;}
        uint64_t wrap=r64(sf+0x28);if(!wrap){usleep(200000);}
        // wrap = 046885<T> (le composant List de sf+0x28). Même layout que PlayerModel : +0x10 set
        uint64_t set=r64(wrap+0x10);if(!set){usleep(200000);continue;}
        uint32_t count=0;rd(set+0x18,&count,4);
        uint64_t arr=r64(set+0x10);
        if(!arr||count>500){usleep(200000);continue;}
        if(!out)out=fopen("/tmp/rr02_radar.json","w");
        ftruncate(fileno(out),0);rewind(out);
        fprintf(out,"{\"local\":{\"x\":0,\"y\":0,\"z\":0},\"players\":[");
        bool first=true;int valid=0;
        for(uint32_t i=0;i<count;i++){
            uint64_t bp=r64(arr+0x20+8*i);if(!bp)continue;
            // bools à 0x398/0x399
            uint8_t b398=0,b399=0;rd(bp+0x398,&b398,1);rd(bp+0x399,&b399,1);
            uint64_t pm=r64(bp+0x3F8);               // PlayerModel
            if(!pm)continue;
            V3 p;rd(pm+0x2F8,&p,12);
            if(!(p.x>-5000&&p.x<5000&&p.z>-5000&&p.z<5000&&p.y>-100&&p.y<1000))continue;
            if(p.x==0&&p.y==0&&p.z==0)continue;
            fprintf(stdout,"bp=0x%llx pm=0x%llx b398=%d b399=%d pos=(%.1f,%.1f,%.1f)\n",
                    (unsigned long long)bp,(unsigned long long)pm,b398,b399,p.x,p.y,p.z);
            fprintf(out,"%s{\"x\":%.2f,\"y\":%.2f,\"z\":%.2f,\"local\":%s}",
                    first?"":",",p.x,p.y,p.z,(b398||b399)?"true":"false");
            first=false;valid++;
        }
        fprintf(out,"]}\n");fflush(out);fflush(stdout);
        fprintf(stderr,"tick v23: %d\n",valid);
        usleep(100000);
    }
}
