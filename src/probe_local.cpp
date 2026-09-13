// probe_local — cherche LocalPlayer.Entity : static_fields du klass BasePlayer (klass+0xB8)
// puis scanne ce bloc pour un pointeur vers un BasePlayer validé (ou vers un objet de klass BasePlayer)
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
static bool name_of(uint64_t a,char*out,size_t n){ uint64_t p=r64(a); if(!p) return false;
    if(!rd(p,out,n-1)) return false; out[n-1]=0; return true; }
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
int main(){
    PID=0; { FILE* f=popen("pgrep -x Rust | head -1","r"); char b[64]; if(f&&fgets(b,64,f)) PID=atoi(b); if(f)pclose(f); }
    if(!PID){ printf("Rust absent\n"); return 1; }
    if(task_for_pid(mach_task_self(),PID,&T)!=KERN_SUCCESS){ printf("task_for_pid KO\n"); return 1; }
    uint64_t kb=find_klass("BasePlayer"), km=find_klass("PlayerModel");
    printf("klass BasePlayer=0x%llx  PlayerModel=0x%llx\n",(unsigned long long)kb,(unsigned long long)km);
    if(!kb||!km) return 1;

    std::vector<uint64_t> cand, bp;
    scan_rw([&](uint64_t cur,unsigned char* buf,size_t got){
        for(size_t i=0;i+8<=got;i+=8) if(*(uint64_t*)(buf+i)==kb) cand.push_back(cur+i);
    });
    for(uint64_t o : cand){ uint64_t m=r64(o+0x328); if(m&&r64(m)==km) bp.push_back(o); }
    printf("BasePlayer validés: %zu\n",bp.size());

    // static_fields du klass BasePlayer
    uint64_t sf=r64(kb+0xB8);
    printf("static_fields (klass+0xB8) = 0x%llx\n",(unsigned long long)sf);
    if(sf){
        std::vector<unsigned char> blk(0x800);
        if(rd(sf,blk.data(),blk.size())){
            printf("--- pointeurs dans les static fields qui sont des BasePlayer connus ---\n");
            int found=0;
            for(size_t i=0;i+8<=blk.size();i+=8){
                uint64_t v=*(uint64_t*)(blk.data()+i);
                if(!v) continue;
                if(std::find(bp.begin(),bp.end(),v)!=bp.end()){
                    printf("  [sf+0x%zX] -> BasePlayer 0x%llx  <== LocalPlayer.Entity probable\n",i,(unsigned long long)v);
                    found++;
                }
            }
            if(!found) printf("  (aucun) — dump des premiers qwords non nuls :\n");
            for(size_t i=0;i<0x60;i+=8){
                uint64_t v=*(uint64_t*)(blk.data()+i);
                if(v) printf("  sf+0x%02zX = 0x%llx\n",i,(unsigned long long)v);
            }
        }
    }
    return 0;
}
