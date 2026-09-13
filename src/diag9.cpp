
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>
static task_t g_task;
static bool rmem(uint64_t a, void* b, size_t s){vm_size_t g=0;return vm_read_overwrite(g_task,(vm_address_t)a,s,(vm_address_t)b,&g)==KERN_SUCCESS&&(size_t)g==s;}
static uint64_t r64(uint64_t a){uint64_t v=0;rmem(a,&v,8);return v;}
static uint64_t spac(uint64_t p){return p & 0x0000FFFFFFFFFFFFULL;}
static bool vp(uint64_t p){uint64_t s=spac(p);return s>0x10000ULL&&s<0x7FFFFFFFFFFFULL;}
struct Rg{uint64_t s,e;};static std::vector<Rg> g_rw;
static void enum_all(){g_rw.clear();mach_vm_address_t a=0;mach_vm_size_t sz;vm_region_basic_info_data_64_t info;mach_msg_type_number_t cnt;mach_port_t obj;
while(true){cnt=VM_REGION_BASIC_INFO_COUNT_64;if(mach_vm_region(g_task,&a,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&cnt,&obj)!=KERN_SUCCESS)break;
g_rw.push_back({a,a+sz});a+=sz;}}
static pid_t find_rust(){pid_t pids[16384];int n=proc_listpids(PROC_ALL_PIDS,0,pids,sizeof(pids));
for(int i=0;i<n/(int)sizeof(pid_t);i++){if(!pids[i])continue;char path[PROC_PIDPATHINFO_MAXSIZE]={};
if(proc_pidpath(pids[i],path,sizeof(path))>0&&strstr(path,"RustClient"))return pids[i];}return -1;}
static std::string read_cstr(uint64_t p,int max=100){char b[112]={};if(!vp(p)||!rmem(p,b,max))return"";b[max]=0;
for(int i=0;i<max;i++){char c=b[i];if(c==0)return std::string(b,i);if((unsigned char)c<0x20||(unsigned char)c>0x7e)return"";}
return std::string(b);}
int main(){
    pid_t pid=find_rust(); if(pid<0){printf("no rust\n");return 1;}
    if(task_for_pid(mach_task_self(),pid,&g_task)!=KERN_SUCCESS){printf("tfp fail\n");return 1;}
    enum_all();
    const size_t C=4*1024*1024; std::vector<uint8_t> buf(C);
    // collect addrs of "BasePlayer\0" strings
    std::unordered_set<uint64_t> str_set;
    const char* pat="BasePlayer";
    for(auto&r:g_rw){uint64_t rs=r.e-r.s;
        for(uint64_t o=0;o<rs;o+=C){uint64_t tr=std::min<uint64_t>(C,rs-o);mach_vm_size_t got=0;
            if(mach_vm_read_overwrite(g_task,r.s+o,tr,(vm_address_t)buf.data(),&got)!=KERN_SUCCESS)break;
            for(size_t i=0;i+10<=got;i++)
                if(buf[i]=='B'&&memcmp(buf.data()+i,pat,10)==0&&(i+10>=got||buf[i+10]==0))
                    str_set.insert(r.s+o+i);}}
    printf("strings: %zu\n",str_set.size());
    // find klass: qword K such that [K+0x10]==str && [K+0x18]=="Rust" namespace.
    // scan RW regions for qwords whose VALUE is a str addr; K = addr_of_qword - 0x10; verify.
    std::unordered_set<uint64_t> klasses;
    for(auto&r:g_rw){uint64_t rs=r.e-r.s;
        for(uint64_t o=0;o<rs;o+=C){uint64_t tr=std::min<uint64_t>(C,rs-o);mach_vm_size_t got=0;
            if(mach_vm_read_overwrite(g_task,r.s+o,tr,(vm_address_t)buf.data(),&got)!=KERN_SUCCESS)break;
            for(size_t i=0;i+8<=got;i+=8){
                uint64_t p;memcpy(&p,buf.data()+i,8);p=spac(p);
                if(str_set.count(p)){
                    uint64_t K=r.s+o+i-0x10;
                    if(!vp(K))continue;
                    std::string ns=read_cstr(spac(r64(K+0x18)),20);
                    if(ns=="Rust"||ns==""){/* accept, verify name */}
                    std::string nm=read_cstr(p,20);
                    if(nm=="BasePlayer")klasses.insert(K);
                }}}}
    printf("BasePlayer klasses found: %zu\n",klasses.size());
    for(auto k:klasses)printf("  klass=0x%llx ns=%s\n",(unsigned long long)k,read_cstr(spac(r64(k+0x18)),20).c_str());
    if(klasses.empty()){printf("none\n");return 1;}
    uint64_t KL=*klasses.begin();
    // single scan: objects whose first qword == KL (managed) OR whose first qword is a vtable whose [0]==KL
    std::vector<uint64_t> managed_objs;
    std::unordered_map<uint64_t,int> vt_cand;
    for(auto&r:g_rw){uint64_t rs=r.e-r.s;if(rs>512ULL*1024*1024)continue;
        for(uint64_t o=0;o<rs;o+=C){uint64_t tr=std::min<uint64_t>(C,rs-o);mach_vm_size_t got=0;
            if(mach_vm_read_overwrite(g_task,r.s+o,tr,(vm_address_t)buf.data(),&got)!=KERN_SUCCESS)break;
            for(size_t i=0;i+8<=got;i+=8){
                uint64_t v;memcpy(&v,buf.data()+i,8);
                if(v==KL)managed_objs.push_back(r.s+o+i);
                else vt_cand[v]++;   // over-collect; verify later cheaply by checking set membership after
                }}}
    printf("managed objects (obj[0]==klass): %zu\n",managed_objs.size());
    // vtable-based: vtables are pointers k in heap; check vt_cand for values whose [0]==KL:
    // too slow to check all; instead scan for qword == KL inside VT region? vtable[0]=KL means
    // the KL value appears as FIRST entry of the vtable array. Those appearances were already
    // counted in managed_objs scan! managed_objs includes vtable[0] slots. Distinguish: a real object
    // is followed by m_CachedPtr etc. Let's just dump candidates with their neighbors.
    int shown=0;
    for(uint64_t ob:managed_objs){
        if(shown++>20)break;
        uint64_t a=spac(r64(ob+8)), b=spac(r64(ob+0x10)), sid700=spac(r64(ob+0x700)), sid1b0=spac(r64(ob+0x1b0));
        printf("  obj 0x%llx: +8=0x%llx +0x10=0x%llx sid@0x700=0x%llx sid@0x1b0=0x%llx\n",
            (unsigned long long)ob,(unsigned long long)a,(unsigned long long)b,
            (unsigned long long)sid700,(unsigned long long)sid1b0);
    }
    return 0;
}
