// find_slot — trouve le slot runtime (TypeInfo) pointant sur une classe IL2CPP donnée,
// en scannant les segments DATA du binaire il2cpp (robuste aux changements de layout metadata).
// Usage: find_slot PlayerModel [BasePlayer ...]
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>
#include <string>
static task_t T=MACH_PORT_NULL;static uint64_t BASE=0;
static bool rd(uint64_t a,void*b,size_t n){mach_vm_size_t g=0;return mach_vm_read_overwrite(T,a,n,(mach_vm_address_t)b,&g)==KERN_SUCCESS&&g==n;}
static uint64_t r64(uint64_t a){uint64_t v=0;rd(a,&v,8);return v;}
static bool ascii(uint64_t a,char*out,int max){uint8_t b[300]={};if(max>255)max=255;if(!rd(a,b,max))return false;int n=0;
  while(n<max-1&&b[n]>=32&&b[n]<=126){out[n]=(char)b[n];n++;}out[n]=0;return n>0;}
struct Img{uint64_t a,s;int prot;};
int main(int argc,char**argv){
    if(argc<2){printf("usage: find_slot <ClassName>...\n");return 1;}
    int bytes=proc_listpids(PROC_ALL_PIDS,0,nullptr,0);
    std::vector<pid_t> ps(bytes/4+256);bytes=proc_listpids(PROC_ALL_PIDS,0,ps.data(),ps.size()*4);
    pid_t pid=0;for(int i=0;i<bytes/4;i++){char p[PROC_PIDPATHINFO_MAXSIZE]={};if(proc_pidpath(ps[i],p,sizeof p)>0&&strstr(p,"/RustClient.app/Contents/MacOS/Rust")){pid=ps[i];break;}}
    if(task_for_pid(mach_task_self(),pid,&T)!=KERN_SUCCESS){printf("TFP_FAIL\n");return 1;}
    task_dyld_info_data_t di={};mach_msg_type_number_t c=TASK_DYLD_INFO_COUNT;
    task_info(T,TASK_DYLD_INFO,(task_info_t)&di,&c);
    struct{uint32_t ver,cnt;uint64_t arr;}im={};rd(di.all_image_info_addr,&im,sizeof im);
    struct I{uint64_t load,path,date;};std::vector<I> ims(im.cnt);rd(im.arr,ims.data(),im.cnt*sizeof(I));
    uint64_t size=0;
    for(auto&i:ims){char p[512]={};if(i.load&&rd(i.path,p,512)&&strstr(p,"GameAssembly.dylib")){BASE=i.load;break;}}
    // taille de l'image via les régions contiguës
    mach_vm_address_t a=BASE;mach_vm_size_t sz=0;vm_region_basic_info_data_64_t inf;mach_msg_type_number_t ic=VM_REGION_BASIC_INFO_COUNT_64;mach_port_t ob=0;
    std::vector<Img> segs;
    while(1){
        mach_vm_address_t q=a;if(mach_vm_region(T,&q,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&inf,&ic,&ob)!=KERN_SUCCESS)break;
        if(q!=a)break;
        segs.push_back({(uint64_t)q,(uint64_t)sz,inf.protection});a=q+sz;
        if(sz==0)break;
    }
    uint64_t tot=0;for(auto&s:segs)tot+=s.s;
    printf("BASE=0x%llx  segments image=%zu  taille totale=%.1f MB\n",(unsigned long long)BASE,segs.size(),tot/1048576.0);

    for(int arg=1;arg<argc;arg++){
        const char* want=argv[arg];
        int found=0;
        for(auto&s:segs){
            if(!(s.prot&VM_PROT_READ))continue;
            const size_t CH=8*1024*1024;
            uint64_t cur=s.a,left=s.s;
            std::vector<uint8_t> buf(CH);
            while(left>0){
                size_t n=(left<CH)?(size_t)left:CH;mach_vm_size_t got=0;
                if(mach_vm_read_overwrite(T,cur,n,(mach_vm_address_t)buf.data(),&got)==KERN_SUCCESS){
                    for(size_t i=0;i+8<=got;i+=8){
                        uint64_t v=*(uint64_t*)(buf.data()+i);
                        if(v<0x1000000||v>0x800000000000ULL)continue;
                        char nm[128]={},ns[128]={};
                        if(!ascii(v+0x10,nm,100))continue;
                        if(strcmp(nm,want))continue;
                        ascii(v+0x18,ns,100);
                        uint64_t sf=r64(v+0xB8);
                        printf("[%s] SLOT=0x%llx (base+0x%llx) klass=0x%llx ns='%s' sf=0x%llx\n",
                            want,(unsigned long long)(cur+i),(unsigned long long)(cur+i-BASE),
                            (unsigned long long)v,ns,(unsigned long long)sf);
                        if(sf)printf("      sf: 0x%llx 0x%llx 0x%llx 0x%llx 0x%llx\n",
                            (unsigned long long)r64(sf),(unsigned long long)r64(sf+8),(unsigned long long)r64(sf+0x10),
                            (unsigned long long)r64(sf+0x18),(unsigned long long)r64(sf+0x20));
                        fflush(stdout);found++;
                    }
                }
                if(left<=n)break;cur+=n;left-=n;
            }
        }
        printf("[%s] total slots: %d\n",want,found);
    }
    return 0;
}
