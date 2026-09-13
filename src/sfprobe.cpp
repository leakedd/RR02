// sfprobe <NomClasse> — static_fields du klass + dump annoté des pointeurs (nom de la classe pointée)
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>
#include <algorithm>

static task_t T; static pid_t PID;
static bool rd(uint64_t a,void*b,size_t n){ mach_vm_size_t g=0;
    return mach_vm_read_overwrite(T,a,n,(mach_vm_address_t)b,&g)==KERN_SUCCESS && g==n; }
static uint64_t r64(uint64_t a){ uint64_t v=0; rd(a,&v,8); return v; }
static bool str_at(uint64_t a,char*out,size_t n){ if(!rd(a,out,n-1)) return false; out[n-1]=0;
    if(!out[0]) return false;
    for(int i=0;out[i];i++) if((unsigned char)out[i]<0x20||(unsigned char)out[i]>0x7e) return false;
    return true; }
static bool name_of(uint64_t a,char*out,size_t n){ uint64_t p=r64(a); if(!p) return false; return str_at(p,out,n); }
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
static uint64_t find_klass(const char* want){
    uint64_t f=0;
    scan_rw([&](uint64_t cur,unsigned char* buf,size_t got){
        if(f||got<0x100) return;
        for(size_t i=0;i+0x88<=got;i+=8){
            uint64_t X=cur+i;
            if(*(uint64_t*)(buf+i+0x78)!=X) continue;
            char nm[128]; if(!name_of(X+0x10,nm,sizeof(nm))) continue;
            if(!strcmp(nm,want)){ f=X; return; }
        }
    });
    return f;
}
int main(int argc,char**argv){
    const char* want = argc>1? argv[1] : "BasePlayer";
    PID=0; { FILE* f=popen("pgrep -x Rust | head -1","r"); char b[64]; if(f&&fgets(b,64,f)) PID=atoi(b); if(f)pclose(f); }
    if(!PID){ printf("Rust absent\n"); return 1; }
    if(task_for_pid(mach_task_self(),PID,&T)!=KERN_SUCCESS){ printf("task_for_pid KO\n"); return 1; }
    uint64_t k=find_klass(want);
    printf("klass %s = 0x%llx\n",want,(unsigned long long)k);
    if(!k) return 1;
    uint64_t sf=r64(k+0xB8);
    printf("static_fields(klass+0xB8) = 0x%llx\n",(unsigned long long)sf);
    if(sf){
        std::vector<unsigned char> blk(0x300);
        if(rd(sf,blk.data(),blk.size())){
            for(size_t i=0;i<0x100;i+=8){
                uint64_t v=*(uint64_t*)(blk.data()+i);
                if(!v||v<0x1000000) continue;
                char s[128], cn[128];
                if(name_of(v,cn,sizeof(cn)) || str_at(v,s,sizeof(s))){
                    printf("  sf+0x%02zX -> 0x%llx  class=%s\n",i,(unsigned long long)v,cn);
                    continue;
                }
                uint64_t inner=r64(v);
                if(inner && (name_of(inner,cn,sizeof(cn))||str_at(inner,s,sizeof(s)))){
                    printf("  sf+0x%02zX -> 0x%llx -> [0]=0x%llx (%s)\n",i,(unsigned long long)v,(unsigned long long)inner,cn);
                } else {
                    printf("  sf+0x%02zX -> 0x%llx (opaque)\n",i,(unsigned long long)v);
                }
            }
        }
    } else printf("(static_fields NULL — classe non initialisée ou pas de champs statiques)\n");
    return 0;
}
