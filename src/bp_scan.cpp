// RR02 bp_scan — énumération des objets BasePlayer (joueurs connectés) par scan du klass
// 1) résout BasePlayer_TypeInfo (VA script.json 0x8D4A110) -> klass runtime
// 2) scanne toutes les régions RW à la recherche de qwords == klass (objet+0 = klass en IL2CPP)
// 3) pour chaque candidat : valide via PlayerModel (+0x3F8) et cherche SteamID (ulong 76561...) + nom (Unity string)
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>
#include <unistd.h>
#include <algorithm>

static task_t T=MACH_PORT_NULL;
static uint64_t BASE=0;
static bool rd(uint64_t a,void*b,size_t n){mach_vm_size_t g=0;return mach_vm_read_overwrite(T,a,n,(mach_vm_address_t)b,&g)==KERN_SUCCESS&&g==n;}
static uint64_t r64(uint64_t a){uint64_t v=0;rd(a,&v,8);return v;}
static uint32_t r32(uint64_t a){uint32_t v=0;rd(a,&v,4);return v;}

static bool is_steamid(uint64_t v){return v>76561197900000000ULL&&v<76561300000000000ULL;}

// lit une chaîne Unity (len @+0x10 int, chars UTF16 @+0x14)
static bool uni_str(uint64_t p,char*out,int max){
    if(!p||p<0x1000000)return false;
    int32_t len=r32(p+0x10); if(len<=0||len>64)return false;
    wchar_t buf[65]={}; if(!rd(p+0x14,buf,len*2))return false;
    int n=0;for(int i=0;i<len&&n<max-1;i++){int c=buf[i];if(c<32||c>126)return false;out[n++]=(char)c;}
    out[n]=0;return n>0;
}

int main(){
    int bytes=proc_listpids(PROC_ALL_PIDS,0,nullptr,0);
    std::vector<pid_t> ps(bytes/4+256);
    bytes=proc_listpids(PROC_ALL_PIDS,0,ps.data(),ps.size()*4);
    pid_t pid=0;
    for(int i=0;i<bytes/4;i++){char p[PROC_PIDPATHINFO_MAXSIZE]={};if(proc_pidpath(ps[i],p,sizeof p)>0&&strstr(p,"/RustClient.app/Contents/MacOS/Rust")){pid=ps[i];break;}}
    if(!pid){printf("NO_RUST\n");return 1;}
    if(task_for_pid(mach_task_self(),pid,&T)!=KERN_SUCCESS){printf("TFP_FAIL\n");return 1;}
    task_dyld_info_data_t di={};mach_msg_type_number_t c=TASK_DYLD_INFO_COUNT;
    task_info(T,TASK_DYLD_INFO,(task_info_t)&di,&c);
    struct{uint32_t ver,cnt;uint64_t arr;}im={};
    rd(di.all_image_info_addr,&im,sizeof im);
    struct Img{uint64_t load,path,date;};Img*ims=new Img[im.cnt];rd(im.arr,ims,im.cnt*sizeof(Img));
    for(uint32_t i=0;i<im.cnt;i++){char p[512]={};if(rd(ims[i].path,p,512)&&strstr(p,"GameAssembly.dylib")){BASE=ims[i].load;break;}}
    delete[] ims;
    printf("BASE=0x%llx\n",(unsigned long long)BASE);
    uint64_t bpTI=r64(BASE+0x8d4a110);
    printf("BasePlayer_TypeInfo slot=0x%llx  klass=0x%llx\n",
           (unsigned long long)r64(BASE+0x8d4a110-0), (unsigned long long)bpTI);
    // affiche nom de la klass (char* à +0x10)
    char kname[128]={};rd(bpTI+0x10,kname,100);printf("klass name=%s\n",kname);
    uint64_t pmTI=r64(BASE+0x8d402f0);
    printf("PlayerModel klass=0x%llx\n",(unsigned long long)pmTI);

    // scan régions RW
    mach_vm_address_t addr=0;mach_vm_size_t size=0;vm_region_basic_info_data_64_t info;mach_msg_type_number_t ic=VM_REGION_BASIC_INFO_COUNT_64;mach_port_t obj=0;
    struct Hit{uint64_t obj;uint64_t pm;uint64_t sid;char name[64];};
    std::vector<Hit> hits;
    int regions=0;
    while(1){
        mach_vm_address_t a=addr;
        kern_return_t kr=mach_vm_region(T,&a,&size,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&ic,&obj);
        if(kr!=KERN_SUCCESS)break;
        addr=a+size;
        if(!(info.protection&VM_PROT_WRITE))continue;
        if(size>512ULL*1024*1024)continue;
        regions++;
        std::vector<uint8_t> buf(size);
        mach_vm_size_t got=0;
        if(mach_vm_read_overwrite(T,a,size,(mach_vm_address_t)buf.data(),&got)!=KERN_SUCCESS)continue;
        for(size_t o=0;o+8<=got;o+=8){
            uint64_t v=*(uint64_t*)(buf.data()+o);
            if(v!=bpTI)continue;
            uint64_t ob=a+o;
            // valide : PlayerModel ptr à +0x3F8
            uint64_t pm=r64(ob+0x3F8);
            if(!pm||pm<0x1000000||(pm&7))continue;
            Hit h={ob,pm,0,{0}};
            // cherche SteamID dans les 0x900 premiers bytes
            uint8_t raw[0x900];if(rd(ob,raw,sizeof raw)){
                for(size_t k=0;k+8<=sizeof raw;k+=8){uint64_t q=*(uint64_t*)(raw+k);if(is_steamid(q)){h.sid=q;break;}}
                // cherche un nom : pointeur vers Unity string
                for(size_t k=0;k+8<=sizeof raw;k+=8){
                    uint64_t p=*(uint64_t*)(raw+k);
                    if(p<0x1000000||(p&1))continue;
                    char nm[64];if(uni_str(p,nm,64)){strncpy(h.name,nm,63);break;}
                }
            }
            hits.push_back(h);
        }
    }
    printf("regions scannées RW: %d — objets BasePlayer trouvés: %zu\n",regions,hits.size());
    for(auto&h:hits)
        printf("  obj=0x%llx pm=0x%llx sid=%llu name=%s\n",(unsigned long long)h.obj,(unsigned long long)h.pm,
               (unsigned long long)h.sid,h.name[0]?h.name:"?");
    return 0;
}
