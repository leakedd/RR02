
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <unordered_map>
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
    // 1. find all "BasePlayer\0" string occurrences in READABLE regions
    const size_t C=4*1024*1024; std::vector<uint8_t> buf(C);
    std::vector<uint64_t> str_addrs;
    const char* pat="BasePlayer";
    for(auto&r:g_rw){uint64_t rs=r.e-r.s;
        for(uint64_t o=0;o<rs;o+=C){uint64_t tr=std::min<uint64_t>(C,rs-o);mach_vm_size_t got=0;
            if(mach_vm_read_overwrite(g_task,r.s+o,tr,(vm_address_t)buf.data(),&got)!=KERN_SUCCESS)break;
            for(size_t i=0;i+10<=got;i++){
                if(buf[i]=='B'&&memcmp(buf.data()+i,pat,10)==0&&(i+10>=got||buf[i+10]==0))
                    str_addrs.push_back(r.s+o+i);}}}
    printf("\"BasePlayer\\0\" strings: %zu\n",str_addrs.size());
    for(int i=0;i<(int)str_addrs.size()&&i<10;i++)printf("  0x%llx\n",(unsigned long long)str_addrs[i]);
    // 2. find Il2CppClass structures pointing to those strings at +0x10
    std::vector<uint64_t> klasses;
    for(auto&r:g_rw){uint64_t rs=r.e-r.s;
        for(uint64_t o=0;o<rs;o+=C){uint64_t tr=std::min<uint64_t>(C,rs-o);mach_vm_size_t got=0;
            if(mach_vm_read_overwrite(g_task,r.s+o,tr,(vm_address_t)buf.data(),&got)!=KERN_SUCCESS)break;
            for(size_t i=0;i+8<=got;i+=8){
                uint64_t p;memcpy(&p,buf.data()+i,8);p=spac(p);
                if((p&0xFFF)==0)continue; // name ptrs not page-aligned typically
                for(uint64_t sa:str_addrs){if(p==sa){klasses.push_back(r.s+o+i-0x10);}}}}}
    printf("candidate klasses: %zu\n",klasses.size());
    std::unordered_map<uint64_t,int> uniq;
    for(auto k:klasses)uniq[k]++;
    for(auto&[k,c]:uniq)printf("  klass=0x%llx (refs x%d)\n",(unsigned long long)k,c);
    // 3. count objects whose [obj+0]==klass or [[obj+0]]==klass (sample scan of RW regions)
    for(auto&[k,c]:uniq){
        int direct=0,indirect=0;
        for(auto&r:g_rw){uint64_t rs=r.e-r.s;if(rs>512ULL*1024*1024)continue;
            for(uint64_t o=0;o<rs;o+=C){uint64_t tr=std::min<uint64_t>(C,rs-o);mach_vm_size_t got=0;
                if(mach_vm_read_overwrite(g_task,r.s+o,tr,(vm_address_t)buf.data(),&got)!=KERN_SUCCESS)break;
                for(size_t i=0;i+8<=got;i+=8){
                    uint64_t v;memcpy(&v,buf.data()+i,8);
                    if(v==k)direct++;
                    else{uint64_t v2=spac(r64(v));if(v2==k)indirect++;}}}}
        printf("klass 0x%llx: direct refs=%d indirect=%d\n",(unsigned long long)k,direct,indirect);
    }
    return 0;
}
