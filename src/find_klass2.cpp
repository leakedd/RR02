// find_klass2 — localise la classe runtime IL2CPP en 2 passes :
//  P1 : trouve les occurrences de la chaîne (heap metadata) -> adresses S
//  P2 : scanne les régions RW à la recherche d'un qword == S  -> le porteur est un Il2CppClass (name @+0x10)
//  Valide : namespaze @+0x18, static_fields @+0xB8, image @+0x0
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>
#include <set>
#include <string>
#include <algorithm>
static task_t T=MACH_PORT_NULL;static uint64_t BASE=0;
static bool rd(uint64_t a,void*b,size_t n){mach_vm_size_t g=0;return mach_vm_read_overwrite(T,a,n,(mach_vm_address_t)b,&g)==KERN_SUCCESS&&g==n;}
static uint64_t r64(uint64_t a){uint64_t v=0;rd(a,&v,8);return v;}
static bool ascii(uint64_t a,char*out,int max){uint8_t b[300]={};if(max>255)max=255;if(!rd(a,b,max))return false;int n=0;
  while(n<max-1&&b[n]>=32&&b[n]<=126){out[n]=(char)b[n];n++;}out[n]=0;return n>0;}
struct Reg{uint64_t a,s;int prot;};
int main(int argc,char**argv){
    const char* want=argv[1];
    int bytes=proc_listpids(PROC_ALL_PIDS,0,nullptr,0);
    std::vector<pid_t> ps(bytes/4+256);bytes=proc_listpids(PROC_ALL_PIDS,0,ps.data(),ps.size()*4);
    pid_t pid=0;for(int i=0;i<bytes/4;i++){char p[PROC_PIDPATHINFO_MAXSIZE]={};if(proc_pidpath(ps[i],p,sizeof p)>0&&strstr(p,"/RustClient.app/Contents/MacOS/Rust")){pid=ps[i];break;}}
    if(task_for_pid(mach_task_self(),pid,&T)!=KERN_SUCCESS){printf("TFP_FAIL\n");return 1;}
    task_dyld_info_data_t di={};mach_msg_type_number_t c=TASK_DYLD_INFO_COUNT;
    task_info(T,TASK_DYLD_INFO,(task_info_t)&di,&c);
    struct{uint32_t ver,cnt;uint64_t arr;}im={};rd(di.all_image_info_addr,&im,sizeof im);
    struct Img{uint64_t load,path,date;};std::vector<Img> ims(im.cnt);rd(im.arr,ims.data(),im.cnt*sizeof(Img));
    for(auto&i:ims){char p[512]={};if(i.load&&rd(i.path,p,512)&&strstr(p,"GameAssembly.dylib")){BASE=i.load;break;}}
    printf("BASE=0x%llx  cible='%s'\n",(unsigned long long)BASE,want);

    std::vector<Reg> regs;
    mach_vm_address_t addr=0;mach_vm_size_t size=0;vm_region_basic_info_data_64_t info;mach_msg_type_number_t ic=VM_REGION_BASIC_INFO_COUNT_64;mach_port_t obj=0;
    while(1){kern_return_t kr=mach_vm_region(T,&addr,&size,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&ic,&obj);if(kr!=KERN_SUCCESS)break;
        if(size>0)regs.push_back({(uint64_t)addr,(uint64_t)size,info.protection});addr+=size;}
    printf("régions: %zu\n",regs.size());

    // P1 : occurrences de la chaîne
    size_t L=strlen(want);std::set<uint64_t> S;
    const size_t CH=4*1024*1024;std::vector<uint8_t> buf(CH+64);
    uint8_t pat[128];memcpy(pat,want,L);pat[L]=0;
    for(auto&r:regs){
        if(!(r.prot&VM_PROT_READ))continue;
        uint64_t cur=r.a,left=r.s;
        while(left>0){size_t n=(left<CH)?(size_t)left:CH;mach_vm_size_t got=0;
            if(mach_vm_read_overwrite(T,cur,n,(mach_vm_address_t)buf.data(),&got)==KERN_SUCCESS&&got>L+1)
                for(size_t i=0;i+L+1<=got;i++)if(buf[i]==pat[0]&&!memcmp(buf.data()+i,pat,L+1))S.insert(cur+i);
            if(left<=n)break;cur+=n;left-=n;}
    }
    printf("occurrences de '%s': %zu\n",want,S.size());

    // P2 : qui pointe sur ces chaînes ?
    int nk=0;
    for(auto&r:regs){
        if(!(r.prot&VM_PROT_WRITE))continue;
        uint64_t cur=r.a,left=r.s;
        while(left>0){size_t n=(left<CH)?(size_t)left:CH;mach_vm_size_t got=0;
            if(mach_vm_read_overwrite(T,cur,n,(mach_vm_address_t)buf.data(),&got)==KERN_SUCCESS){
                for(size_t i=0;i+8<=got;i+=8){
                    uint64_t v=*(uint64_t*)(buf.data()+i);
                    if(!S.count(v))continue;
                    uint64_t kl=cur+i-0x10;
                    char nm[128]={},ns[128]={},img[128]={},mtd[128]={};
                    bool okn=ascii(kl+0x10,nm,100),okns=ascii(kl+0x18,ns,100);
                    if(!okn||strcmp(nm,want))continue;
                    uint64_t imp=r64(kl+0x0); ascii(imp,img,80);
                    uint64_t sf=r64(kl+0xB8);
                    uint64_t mcount=0, mptr=r64(kl+0x108); uint32_t mc=0; rd(kl+0x100,&mc,4);
                    sprintf(mtd,"methods=%u@0x%llx",mc,(unsigned long long)mptr);
                    printf("KLASS 0x%llx name='%s' ns='%s' image='%s' sf=0x%llx %s\n",
                        (unsigned long long)kl,nm,okns?ns:"?",img,(unsigned long long)sf,mtd);
                    if(sf){printf("    sf[0]=0x%llx sf[1]=0x%llx sf[2]=0x%llx sf[3]=0x%llx sf[4]=0x%llx\n",
                        (unsigned long long)r64(sf),(unsigned long long)r64(sf+8),(unsigned long long)r64(sf+16),
                        (unsigned long long)r64(sf+24),(unsigned long long)r64(sf+32));}
                    fflush(stdout);nk++;
                }
            }
            if(left<=n)break;cur+=n;left-=n;}
    }
    printf("klasses trouvés: %d\n",nk);
    return 0;
}
