// bploc — où vivent les BasePlayer ? (regions, volume) pour réduire le scan
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>
#include <map>
#include <algorithm>

static task_t T;
static bool rd(uint64_t a,void*b,size_t n){ mach_vm_size_t g=0;
    return mach_vm_read_overwrite(T,a,n,(mach_vm_address_t)b,&g)==KERN_SUCCESS && g==n; }
static uint64_t r64(uint64_t a){ uint64_t v=0; rd(a,&v,8); return v; }
static bool str_at(uint64_t a,char*out,size_t n){ if(!rd(a,out,n-1)) return false; out[n-1]=0; if(!out[0]) return false;
    for(int i=0;out[i];i++) if((unsigned char)out[i]<0x20||(unsigned char)out[i]>0x7e) return false; return true; }
struct Reg{ uint64_t a,sz; };
static std::vector<Reg> R;
static void regions(){ mach_vm_address_t a=0x100000000ULL;
    for(;;){ mach_vm_address_t q=a; mach_vm_size_t sz=0; vm_region_basic_info_data_64_t bi; mach_port_t ob=0;
        mach_msg_type_number_t ci=VM_REGION_BASIC_INFO_COUNT_64;
        if(mach_vm_region(T,&q,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&bi,&ci,&ob)!=KERN_SUCCESS) break;
        if(sz>0&&(bi.protection&VM_PROT_READ)&&(bi.protection&VM_PROT_WRITE)) R.push_back({q,sz});
        if(q+sz<=a) break; a=q+sz; } }
static int reg_of(uint64_t x){ int lo=0,hi=(int)R.size()-1;
    while(lo<=hi){int m=(lo+hi)/2; if(x<R[m].a)hi=m-1; else if(x>=R[m].a+R[m].sz)lo=m+1; else return m;} return -1; }
static uint64_t find_klass(const char* want){
    const size_t CH=8u<<20; std::vector<unsigned char> buf(CH); uint64_t f=0;
    for(auto&r:R){ for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+0x88<=(size_t)g;i+=8){ uint64_t X=c+i;
            if(*(uint64_t*)(buf.data()+i+0x78)!=X) continue;
            uint64_t p=r64(X+0x10); if(!p) continue; char nm[128]; if(!str_at(p,nm,sizeof(nm))) continue;
            if(!strcmp(nm,want)){ f=X; goto done; } } } }
 done: return f;
}
int main(){
    pid_t PID=0; { FILE* f=popen("pgrep -x Rust | head -1","r"); char b[64]; if(f&&fgets(b,64,f)) PID=atoi(b); if(f)pclose(f); }
    if(!PID||task_for_pid(mach_task_self(),PID,&T)!=KERN_SUCCESS){ printf("KO\n"); return 1; }
    regions(); uint64_t tot=0; for(auto&r:R) tot+=r.sz;
    uint64_t kb=find_klass("BasePlayer"), km=find_klass("PlayerModel");
    printf("klass BP=0x%llx PM=0x%llx | %zu regions RW, %.2f Go\n",(unsigned long long)kb,(unsigned long long)km,R.size(),tot/1073741824.0);
    if(!kb||!km) return 1;
    const size_t CH=8u<<20; std::vector<unsigned char> buf(CH);
    std::vector<uint64_t> cand;
    for(auto&r:R){ for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+8<=(size_t)g;i+=8) if(*(uint64_t*)(buf.data()+i)==kb) cand.push_back(c+i); } }
    std::vector<uint64_t> bp;
    for(uint64_t o:cand){ uint64_t m=r64(o+0x328); if(m&&r64(m)==km) bp.push_back(o); }
    printf("candidats=%zu valides=%zu\n",cand.size(),bp.size());
    std::map<int,int> per; uint64_t mn=~0ULL,mx=0;
    for(uint64_t o:bp){ int i=reg_of(o); per[i]++; mn=std::min(mn,o); mx=std::max(mx,o); }
    uint64_t vol=0; for(auto&kv:per) if(kv.first>=0) vol+=R[kv.first].sz;
    printf("regions contenant des BP: %zu | volume de ces regions: %.2f Go (sur %.2f Go)\n",per.size(),vol/1073741824.0,tot/1073741824.0);
    printf("plage d'adresses: 0x%llx .. 0x%llx (%.2f Go)\n",(unsigned long long)mn,(unsigned long long)mx,(mx-mn)/1073741824.0);
    // distribution par tranches de 1 Go
    std::map<uint64_t,int> giga; for(uint64_t o:bp) giga[(o>>30)<<30]++;
    printf("par tranche de 1 Go :\n"); for(auto&kv:giga) printf("  0x%llx : %d BP\n",(unsigned long long)kv.first,kv.second);
    // candidats (non validés) : où sont-ils ?
    std::map<int,int> pc; for(uint64_t o:cand){ int i=reg_of(o); if(i>=0) pc[i]++; }
    uint64_t volc=0; for(auto&kv:pc) volc+=R[kv.first].sz;
    printf("regions contenant des CANDIDATS: %zu | volume %.2f Go\n",pc.size(),volc/1073741824.0);
    return 0;
}
