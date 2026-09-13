
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
int main(){
    pid_t pid=find_rust(); if(pid<0){printf("no rust\n");return 1;}
    if(task_for_pid(mach_task_self(),pid,&g_task)!=KERN_SUCCESS){printf("tfp fail\n");return 1;}
    enum_all();
    const size_t C=4*1024*1024; std::vector<uint8_t> buf(C);
    // 1. "BasePlayer\0" strings
    std::vector<uint64_t> str_addrs;
    const char* pat="BasePlayer";
    for(auto&r:g_rw){uint64_t rs=r.e-r.s;
        for(uint64_t o=0;o<rs;o+=C){uint64_t tr=std::min<uint64_t>(C,rs-o);mach_vm_size_t got=0;
            if(mach_vm_read_overwrite(g_task,r.s+o,tr,(vm_address_t)buf.data(),&got)!=KERN_SUCCESS)break;
            for(size_t i=0;i+10<=got;i++)
                if(buf[i]=='B'&&memcmp(buf.data()+i,pat,10)==0&&(i+10>=got||buf[i+10]==0))
                    str_addrs.push_back(r.s+o+i);}}
    printf("strings: %zu\n",str_addrs.size());
    for(int i=0;i<(int)str_addrs.size()&&i<8;i++)printf("  str 0x%llx\n",(unsigned long long)str_addrs[i]);
    // 2. klass ptrs
    std::unordered_set<uint64_t> kuniq;
    for(auto&r:g_rw){uint64_t rs=r.e-r.s;
        for(uint64_t o=0;o<rs;o+=C){uint64_t tr=std::min<uint64_t>(C,rs-o);mach_vm_size_t got=0;
            if(mach_vm_read_overwrite(g_task,r.s+o,tr,(vm_address_t)buf.data(),&got)!=KERN_SUCCESS)break;
            for(size_t i=0;i+8<=got;i+=8){
                uint64_t p;memcpy(&p,buf.data()+i,8);p=spac(p);
                if((p&0xFFF)==0)continue;
                for(uint64_t sa:str_addrs)if(p==sa)kuniq.insert(r.s+o+i-0x10);}}}
    printf("klasses: %zu\n",kuniq.size());
    for(auto k:kuniq)printf("  klass 0x%llx\n",(unsigned long long)k);
    // 3. object counts: single scan collecting qwords equal to klass (direct) and qwords whose value
    //    is a candidate vtable addr — verify vtables AFTER scan (r64 on sampled addrs only).
    // First: which regions likely hold objects? Collect ALL qwords == klass (direct objects)
    std::unordered_map<uint64_t,int> direct;   // klass -> count
    std::unordered_map<uint64_t,int> vt_hits;  // value -> count (candidate vtables)
    std::vector<uint64_t> kvec(kuniq.begin(),kuniq.end());
    for(auto&r:g_rw){uint64_t rs=r.e-r.s;if(rs>512ULL*1024*1024)continue;
        for(uint64_t o=0;o<rs;o+=C){uint64_t tr=std::min<uint64_t>(C,rs-o);mach_vm_size_t got=0;
            if(mach_vm_read_overwrite(g_task,r.s+o,tr,(vm_address_t)buf.data(),&got)!=KERN_SUCCESS)break;
            for(size_t i=0;i+8<=got;i+=8){
                uint64_t v;memcpy(&v,buf.data()+i,8);
                for(uint64_t k:kvec)if(v==k){direct[k]++;goto next;}
                vt_hits[v]++;   // candidate vtable (over-collects, fine: it's a hash map)
                next:;}}}
    printf("\ndirect object refs per klass:\n");
    for(auto&[k,c]:direct)printf("  klass 0x%llx: %d direct objects\n",(unsigned long long)k,c);
    // check indirect: for top candidate vtable values, read [v] and compare with klass
    int checked=0;
    std::unordered_map<uint64_t,int> indirect;
    for(auto&[v,c]:vt_hits){
        if(c<2||checked>20000)continue;
        checked++;
        uint64_t k=spac(r64(v));
        if(kuniq.count(k))indirect[k]+=c;
    }
    printf("\nindirect (obj -> vt -> klass):\n");
    for(auto&[k,c]:indirect)printf("  klass 0x%llx: %d objects via vtable\n",(unsigned long long)k,c);
    return 0;
}
