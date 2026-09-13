// fieldscan — classe les instances PlayerModel : imprime position + champs candidats
// (qword à +0x2C0, octets 0x370..0x3A0, quaternion à +0x3A0) pour comparer vivant vs pool
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>
#include <cmath>
#include <algorithm>

static task_t T; static pid_t PID;
static bool rd(uint64_t a, void* b, size_t n){
    mach_vm_size_t g=0;
    return mach_vm_read_overwrite(T,a,n,(mach_vm_address_t)b,&g)==KERN_SUCCESS && g==n;
}
static uint64_t r64(uint64_t a){ uint64_t v=0; rd(a,&v,8); return v; }
static bool name_of(uint64_t a, char* out, size_t n){
    uint64_t p=r64(a); if(!p) return false;
    if(!rd(p,out,n-1)) return false; out[n-1]=0; return true;
}
template<typename F> static void scan_rw(F cb){
    mach_vm_address_t a=0x100000000ULL;
    for(;;){
        mach_vm_address_t q=a; mach_vm_size_t sz=0; vm_region_basic_info_data_64_t bi; mach_port_t ob=0;
        mach_msg_type_number_t ci=VM_REGION_BASIC_INFO_COUNT_64;
        if(mach_vm_region(T,&q,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&bi,&ci,&ob)!=KERN_SUCCESS) break;
        if(sz>0 && (bi.protection&VM_PROT_READ) && (bi.protection&VM_PROT_WRITE)){
            const size_t CH=4u<<20; std::vector<unsigned char> buf(CH);
            for(uint64_t cur=q; cur<q+sz; cur+=CH){
                size_t wn=(size_t)std::min<uint64_t>(CH,q+sz-cur); mach_vm_size_t got=0;
                if(mach_vm_read_overwrite(T,cur,wn,(mach_vm_address_t)buf.data(),&got)!=KERN_SUCCESS) continue;
                cb(cur,buf.data(),(size_t)got);
            }
        }
        if(q+sz<=a) break; a=q+sz;
    }
}
int main(){
    PID=0; { FILE* f=popen("pgrep -x Rust | head -1","r"); char b[64]; if(f&&fgets(b,64,f)) PID=atoi(b); if(f)pclose(f); }
    if(!PID){ printf("Rust absent\n"); return 1; }
    if(task_for_pid(mach_task_self(),PID,&T)!=KERN_SUCCESS){ printf("task_for_pid KO\n"); return 1; }
    uint64_t klass=0;
    scan_rw([&](uint64_t cur,unsigned char* buf,size_t got){
        if(klass||got<0x100) return;
        for(size_t i=0;i+0x88<=got;i+=8){
            uint64_t X=cur+i;
            if(*(uint64_t*)(buf+i+0x78)!=X) continue;
            char nm[128]; if(!name_of(X+0x10,nm,sizeof(nm))) continue;
            if(!strcmp(nm,"PlayerModel")){ klass=X; return; }
        }
    });
    if(!klass){ printf("klass introuvable\n"); return 1; }
    printf("klass=0x%llx\n",(unsigned long long)klass);
    std::vector<uint64_t> inst;
    scan_rw([&](uint64_t cur,unsigned char* buf,size_t got){
        for(size_t i=0;i+8<=got;i+=8) if(*(uint64_t*)(buf+i)==klass) inst.push_back(cur+i);
    });
    printf("instances: %zu\n",inst.size());
    printf("%-14s %-26s %-12s %-14s %-24s %s\n","obj","pos(x,y,z)","0x2C0","0x375|0x37C","quat@0x3A0","0x328");
    int shown=0;
    for(uint64_t o : inst){
        float v[3]={0,0,0}; if(!rd(o+0x2F8,v,12)) continue;
        bool ok = std::isfinite(v[0])&&std::isfinite(v[1])&&std::isfinite(v[2])
               && fabsf(v[0])<6000&&fabsf(v[2])<6000
               && v[1]>0.5f && v[1]<900.0f
               && (fabsf(v[0])>1.0f || fabsf(v[2])>1.0f);
        if(!ok) continue;
        uint64_t f2c0=r64(o+0x2C0);
        unsigned char b375=0,b37c=0; rd(o+0x375,&b375,1); rd(o+0x37C,&b37c,1);
        float q[4]={0,0,0,0}; rd(o+0x3A0,q,16);
        float p328[4]={0,0,0,0}; rd(o+0x328,p328,16);
        printf("%-14llx (%7.1f,%6.1f,%7.1f)  %-12llx %3u | %-8u  (%.2f,%.2f,%.2f,%.2f) (%.1f,%.1f,%.1f)\n",
            (unsigned long long)o, v[0],v[1],v[2], (unsigned long long)f2c0, b375, b37c,
            q[0],q[1],q[2],q[3], p328[0],p328[1],p328[2]);
        if(++shown>=45) break;
    }
    return 0;
}
