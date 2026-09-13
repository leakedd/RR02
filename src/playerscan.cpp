// playerscan — énumère les BasePlayer et lit : playerFlags(+0x6D8), userID(+0x360), PlayerModel(+0x328)
// puis la position du modèle. Décode Connected(0x100) / Sleeping(0x10) / Wounded(0x40)
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
    if(!kb) return 1;
    std::vector<uint64_t> bp;
    scan_rw([&](uint64_t cur,unsigned char* buf,size_t got){
        for(size_t i=0;i+8<=got;i+=8) if(*(uint64_t*)(buf+i)==kb) bp.push_back(cur+i);
    });
    printf("instances BasePlayer: %zu\n",bp.size());
    printf("%-14s %-20s %-11s %-34s %s\n","BasePlayer","userID","flags","décodage","pos(modèle)");
    int conn=0,sleep=0,other=0,shown=0;
    for(uint64_t o : bp){
        uint64_t mdl0=r64(o+0x328);
        if(!mdl0) continue;
        if(r64(mdl0)!=km) continue;              // validation : +0x328 pointe un vrai PlayerModel
        uint32_t fl=0; if(!rd(o+0x6D8,&fl,4)) continue;
        uint64_t uid=r64(o+0x360);
        uint64_t mdl=r64(o+0x328);
        float v[3]={0,0,0}; bool have=false;
        if(mdl){ if(rd(mdl+0x2F8,v,12)) have=std::isfinite(v[0])&&std::isfinite(v[2])&&fabsf(v[0])<6000&&fabsf(v[2])<6000; }
        char dec[64]="";
        if(fl&0x100) strcat(dec,"Connected ");
        if(fl&0x10)  strcat(dec,"Sleeping ");
        if(fl&0x40)  strcat(dec,"Wounded ");
        if(fl&0x04)  strcat(dec,"Admin ");
        if(fl&0x08)  strcat(dec,"ReceivingSnap ");
        if((fl&0x100)&&!(fl&0x10)) conn++;
        else if(fl&0x10) sleep++;
        else other++;
        printf("%-14llx %-20llu 0x%-9x %-34s %s\n",(unsigned long long)o,(unsigned long long)uid,fl,dec,
               have?(""/*placeholder*/):"");
        if(have && shown<70){ printf("        -> modèle 0x%llx  pos=(%.1f, %.1f, %.1f)\n",
            (unsigned long long)mdl, v[0],v[1],v[2]); shown++; }
    }
    printf("\nRÉSUMÉ: connected=%d  sleeping=%d  autre=%d  (total %zu)\n",conn,sleep,other,bp.size());
    return 0;
}
