// bench_scan — mesure : régions RW, débit du scan mono-thread vs multi-thread
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>
#include <thread>
#include <atomic>
#include <chrono>
#include <algorithm>

static task_t T; static pid_t PID;
static bool rd(uint64_t a,void*b,size_t n){ mach_vm_size_t g=0;
    return mach_vm_read_overwrite(T,a,n,(mach_vm_address_t)b,&g)==KERN_SUCCESS && g==n; }
static uint64_t r64(uint64_t a){ uint64_t v=0; rd(a,&v,8); return v; }
static bool str_at(uint64_t a,char*out,size_t n){ if(!rd(a,out,n-1)) return false; out[n-1]=0;
    if(!out[0]) return false; for(int i=0;out[i];i++) if((unsigned char)out[i]<0x20||(unsigned char)out[i]>0x7e) return false; return true; }
static bool name_of(uint64_t a,char*o,size_t n){ uint64_t p=r64(a); return p&&str_at(p,o,n); }

struct Reg{ uint64_t a,sz; };
static std::vector<Reg> regions(){
    std::vector<Reg> v; mach_vm_address_t a=0x100000000ULL;
    for(;;){ mach_vm_address_t q=a; mach_vm_size_t sz=0; vm_region_basic_info_data_64_t bi; mach_port_t ob=0;
        mach_msg_type_number_t ci=VM_REGION_BASIC_INFO_COUNT_64;
        if(mach_vm_region(T,&q,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&bi,&ci,&ob)!=KERN_SUCCESS) break;
        if(sz>0&&(bi.protection&VM_PROT_READ)&&(bi.protection&VM_PROT_WRITE)) v.push_back({q,sz});
        if(q+sz<=a) break; a=q+sz; }
    return v;
}
// travail identique à la découverte de klass : auto-référence +0x78 puis nom
static void work(uint64_t cur,unsigned char*buf,size_t got,int*found){
    if(*found) return;
    for(size_t i=0;i+0x88<=got;i+=8){
        uint64_t X=cur+i;
        if(*(uint64_t*)(buf+i+0x78)!=X) continue;
        char nm[128]; if(!name_of(X+0x10,nm,sizeof(nm))) continue;
        (*found)++;
    }
}
int main(){
    PID=0; { FILE* f=popen("pgrep -x Rust | head -1","r"); char b[64]; if(f&&fgets(b,64,f)) PID=atoi(b); if(f)pclose(f); }
    if(!PID){ printf("Rust absent\n"); return 1; }
    if(task_for_pid(mach_task_self(),PID,&T)!=KERN_SUCCESS){ printf("task_for_pid KO\n"); return 1; }
    auto R=regions(); uint64_t tot=0; for(auto&r:R) tot+=r.sz;
    printf("regions RW: %zu | total %.2f Go\n",R.size(),tot/1073741824.0);
    auto S=R; std::sort(S.begin(),S.end(),[](const Reg&a,const Reg&b){return a.sz>b.sz;});
    printf("top 8 regions:\n"); for(int i=0;i<8&&i<(int)S.size();i++)
        printf("  0x%012llx  %.2f Go\n",(unsigned long long)S[i].a,S[i].sz/1073741824.0);
    double cum=0; for(size_t i=0;i<S.size();i++){ cum+=S[i].sz; if(cum>tot*0.9){ printf("  90%% du volume dans %zu regions (sur %zu)\n",i+1,S.size()); break; } }

    const size_t CH=8u<<20;
    // mono-thread
    { int found=0; std::vector<unsigned char> buf(CH);
      auto t0=std::chrono::steady_clock::now(); uint64_t done=0;
      for(auto&r:R){ for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
          mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
          done+=g; work(c,buf.data(),(size_t)g,&found); } }
      double s=std::chrono::duration<double>(std::chrono::steady_clock::now()-t0).count();
      printf("MONO  : %.1f s | %.0f Mo/s | %llu Mo lus | %d matches\n",s,done/1048576.0/s,(unsigned long long)(done/1048576),found); }

    for(int NT : {4,8,12}){
        std::atomic<size_t> idx{0}; std::atomic<uint64_t> done{0}; std::atomic<int> found{0};
        auto t0=std::chrono::steady_clock::now();
        std::vector<std::thread> th;
        for(int t=0;t<NT;t++) th.emplace_back([&](){ std::vector<unsigned char> buf(CH);
            for(;;){ size_t i=idx++; if(i>=R.size()) break; auto&r=R[i];
                for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
                    mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
                    done+=g; int f=found.load(); work(c,buf.data(),(size_t)g,&f); found.store(f); } } });
        for(auto&x:th) x.join();
        double s=std::chrono::duration<double>(std::chrono::steady_clock::now()-t0).count();
        printf("X%-2d   : %.1f s | %.0f Mo/s | %d matches\n",NT,s,done.load()/1048576.0/s,found.load()); }
    return 0;
}
