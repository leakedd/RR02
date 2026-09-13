// find_klass — retrouve les vrai klasses runtime IL2CPP par scan de la chaîne de nom
// puis vérifie les candidats klass = hit-0x10 (name @klass+0x10, namespaze @+0x18, static_fields @+0xB8)
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#include <cstdio>
#include <cstring>
#include <vector>
#include <cstdint>
#include <string>
static task_t T=MACH_PORT_NULL;static uint64_t BASE=0;
static bool rd(uint64_t a,void*b,size_t n){mach_vm_size_t g=0;return mach_vm_read_overwrite(T,a,n,(mach_vm_address_t)b,&g)==KERN_SUCCESS&&g==n;}
static uint64_t r64(uint64_t a){uint64_t v=0;rd(a,&v,8);return v;}
static bool ascii(uint64_t a,char*out,int max,int*len=nullptr){
    uint8_t b[256]={};if(!rd(a,b,std::min(255,max)))return false;int n=0;
    while(n<max-1&&b[n]){if(b[n]<32||b[n]>126)return false;out[n]=(char)b[n];n++;}
    out[n]=0;if(len)*len=n;return n>0;
}
int main(int argc,char**argv){
    const char* want=argc>1?argv[1]:"PlayerModel";
    int bytes=proc_listpids(PROC_ALL_PIDS,0,nullptr,0);
    std::vector<pid_t> ps(bytes/4+256);bytes=proc_listpids(PROC_ALL_PIDS,0,ps.data(),ps.size()*4);
    pid_t pid=0;for(int i=0;i<bytes/4;i++){char p[PROC_PIDPATHINFO_MAXSIZE]={};if(proc_pidpath(ps[i],p,sizeof p)>0&&strstr(p,"/RustClient.app/Contents/MacOS/Rust")){pid=ps[i];break;}}
    if(task_for_pid(mach_task_self(),pid,&T)!=KERN_SUCCESS){printf("TFP_FAIL\n");return 1;}
    task_dyld_info_data_t di={};mach_msg_type_number_t c=TASK_DYLD_INFO_COUNT;
    task_info(T,TASK_DYLD_INFO,(task_info_t)&di,&c);
    struct{uint32_t ver,cnt;uint64_t arr;}im={};rd(di.all_image_info_addr,&im,sizeof im);
    struct Img{uint64_t load,path,date;};std::vector<Img> ims(im.cnt);rd(im.arr,ims.data(),im.cnt*sizeof(Img));
    for(auto&i:ims){char p[512]={};if(i.load&&rd(i.path,p,512)&&strstr(p,"GameAssembly.dylib")){BASE=i.load;break;}}

    // 1) slot TypeInfo : teste plusieurs hypothèses de déréférencement
    uint64_t slots[2];int ns=0;
    if(argc>2){slots[ns++]=strtoull(argv[2],nullptr,16);}
    for(int i=0;i<ns;i++){
        uint64_t v=r64(BASE+slots[i]);
        printf("slot 0x%llx -> 0x%llx\n",(unsigned long long)slots[i],(unsigned long long)v);
        uint64_t cands[3]={v,r64(v),r64(v+0x8)};
        for(int k=0;k<3;k++){
            char nm[128]={},ns2[128]={};
            bool okn=ascii(cands[k]+0x10,nm,100),okns=ascii(cands[k]+0x18,ns2,100);
            printf("   hyp%d 0x%llx name='%s' ns='%s' sf=0x%llx\n",k,(unsigned long long)cands[k],
                   okn?nm:"?",okns?ns2:"?",(unsigned long long)r64(cands[k]+0xB8));
        }
    }
    // 2) scan de la chaîne de nom
    mach_vm_address_t addr=0;mach_vm_size_t size=0;vm_region_basic_info_data_64_t info;mach_msg_type_number_t ic=VM_REGION_BASIC_INFO_COUNT_64;mach_port_t obj=0;
    size_t L=strlen(want);int found=0;
    while(1){
        kern_return_t kr=mach_vm_region(T,&addr,&size,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&ic,&obj);
        if(kr!=KERN_SUCCESS)break;
        mach_vm_address_t cur=addr;mach_vm_size_t left=size;addr+=size;
        if(size>4ULL*1024*1024*1024)continue;
        const size_t CH=4*1024*1024;
        static std::vector<uint8_t> buf(CH+64);
        while(left>0){
            size_t n=(left<CH)?(size_t)left:CH;
            mach_vm_size_t got=0;
            if(mach_vm_read_overwrite(T,cur,n,(mach_vm_address_t)buf.data(),&got)==KERN_SUCCESS&&got>L+1){
                uint8_t pat[64];memcpy(pat,want,L);pat[L]=0;
                for(size_t i=0;i+L+1<=got;i++){
                    if(buf[i]!=pat[0])continue;
                    if(memcmp(buf.data()+i,pat,L+1))continue;
                    uint64_t hit=cur+i;uint64_t kl=hit-0x10;
                    char nm[128]={},ns2[128]={};int nl=0;
                    if(!ascii(kl+0x10,nm,100,&nl))continue;
                    ascii(kl+0x18,ns2,100);
                    uint64_t sf=r64(kl+0xB8);
                    uint64_t img=r64(kl+0x0);
                    printf("HIT addr=0x%llx klass=0x%llx name='%s' ns='%s' image=0x%llx sf=0x%llx\n",
                           (unsigned long long)hit,(unsigned long long)kl,nm,ns2,(unsigned long long)img,(unsigned long long)sf);
                    fflush(stdout);found++;
                }
            }
            if(left<=n)break;
            cur+=n;left-=n;
        }
    }
    printf("total hits: %d\n",found);
    return 0;
}
