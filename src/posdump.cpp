// posdump — pour une classe : trouve les instances (obj+0x00 == klass), lit les Vector3 +0x2F8/+0x304
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <cmath>

static task_t T; static pid_t P;
static bool rd(uint64_t a, void*b, size_t n){ mach_vm_size_t g=0; return mach_vm_read_overwrite(T,a,n,(mach_vm_address_t)b,&g)==KERN_SUCCESS && g==n; }
static uint64_t r64(uint64_t a){ uint64_t v=0; rd(a,&v,8); return v; }

int main(int argc,char**argv){
    uint64_t want=strtoull(argv[1],0,16);
    char path[4096]; proc_pidpath(getpid(),path,sizeof(path));
    const char* l=strrchr(path,'/'); char exe[4096]; snprintf(exe,sizeof(exe),"%s/RustClient", path[0]?(l?strndup(path,l-path):path):".");
    P=0; { FILE* f=popen("pgrep -x Rust | head -1","r"); char b[64]; if(f&&fgets(b,64,f)) P=atoi(b); if(f)pclose(f);}
    if(!P){ printf("RustClient introuvable\n"); return 1; }
    if(task_for_pid(mach_task_self(),P,&T)!=KERN_SUCCESS){ printf("task_for_pid KO (root ?)\n"); return 1; }
    printf("RustClient pid=%d  classe=0x%llx\n",P,(unsigned long long)want);

    std::vector<uint64_t> hits;
    mach_vm_address_t a=0x100000000ULL;
    while(hits.size()<20000){
        mach_vm_address_t q=a; mach_vm_size_t sz=0; vm_region_basic_info_data_64_t bi; mach_port_t ob=0; mach_msg_type_number_t ci=VM_REGION_BASIC_INFO_COUNT_64;
        if(mach_vm_region(T,&q,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&bi,&ci,&ob)!=KERN_SUCCESS) break;
        if(sz>0 && (bi.protection&VM_PROT_READ) && (bi.protection&VM_PROT_WRITE)){
            std::vector<unsigned char> buf(4u<<20);
            for(uint64_t cur=q; cur<q+sz; cur+=buf.size()){
                size_t want_n=(size_t)std::min<uint64_t>(buf.size(), q+sz-cur);
                mach_vm_size_t got=0;
                if(mach_vm_read_overwrite(T,cur,want_n,(mach_vm_address_t)buf.data(),&got)!=KERN_SUCCESS) continue;
                for(size_t i=0;i+8<=got;i+=8) if(*(uint64_t*)(buf.data()+i)==want) hits.push_back(cur+i);
            }
        }
        if(q+sz<=a) break; a=q+sz;
    }
    printf("instances (obj+0x00 == classe): %zu\n",hits.size());
    int good=0, shown=0;
    for(uint64_t o : hits){
        float v1[3]={0,0,0}, v2[3]={0,0,0};
        if(!rd(o+0x2F8,v1,12)) continue;
        rd(o+0x304,v2,12);
        bool ok = std::isfinite(v1[0])&&std::isfinite(v1[1])&&std::isfinite(v1[2])
               && fabsf(v1[0])<6000 && fabsf(v1[2])<6000 && v1[1]>-150 && v1[1]<900
               && (fabsf(v1[0])>0.5f || fabsf(v1[2])>0.5f);
        if(ok){
            good++;
            if(shown<40){ printf("obj=%llx  pos=(%.1f, %.1f, %.1f)  v2=(%.1f, %.1f, %.1f)\n",
                (unsigned long long)o, v1[0],v1[1],v1[2], v2[0],v2[1],v2[2]); shown++; }
        }
    }
    printf("positions plausibles: %d / %zu\n",good,hits.size());
    return 0;
}
