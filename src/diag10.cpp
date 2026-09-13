
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
    // 1. strings "BasePlayer\0" inside range 0x100000000-0x140000000 (GA/metadata loaded area)
    std::unordered_set<uint64_t> str_set;
    const char* pat="BasePlayer";
    for(auto&r:g_rw){uint64_t rs=r.e-r.s;
        for(uint64_t o=0;o<rs;o+=C){uint64_t tr=std::min<uint64_t>(C,rs-o);mach_vm_size_t got=0;
            if(mach_vm_read_overwrite(g_task,r.s+o,tr,(vm_address_t)buf.data(),&got)!=KERN_SUCCESS)break;
            for(size_t i=0;i+10<=got;i++)
                if(buf[i]=='B'&&memcmp(buf.data()+i,pat,10)==0&&(i+10>=got||buf[i+10]==0)){
                    uint64_t a=r.s+o+i;
                    if(a>=0x100000000ULL&&a<0x140000000ULL)str_set.insert(a);
                }}}
    printf("in-range strings: %zu\n",str_set.size());
    for(auto s:str_set)printf("  str 0x%llx = \"%s\"\n",(unsigned long long)s,read_cstr(s,20).c_str());
    // 2. klass candidates: qword in range whose value == str (klass+0x10 == name ptr)
    std::unordered_set<uint64_t> klasses;
    for(auto&r:g_rw){uint64_t rs=r.e-r.s;
        for(uint64_t o=0;o<rs;o+=C){uint64_t tr=std::min<uint64_t>(C,rs-o);mach_vm_size_t got=0;
            if(mach_vm_read_overwrite(g_task,r.s+o,tr,(vm_address_t)buf.data(),&got)!=KERN_SUCCESS)break;
            for(size_t i=0;i+8<=got;i+=8){
                uint64_t p;memcpy(&p,buf.data()+i,8);p=spac(p);
                if(str_set.count(p)){uint64_t K=r.s+o+i-0x10;
                    if(K>=0x100000000ULL&&K<0x140000000ULL)klasses.insert(K);}}}}
    printf("klass candidates: %zu\n",klasses.size());
    // verify each: name cstr at +0x10, ns at +0x18
    std::vector<uint64_t> real_kl;
    for(uint64_t K:klasses){
        std::string nm=read_cstr(spac(r64(K+0x10)),20);
        std::string ns=read_cstr(spac(r64(K+0x18)),20);
        if(nm=="BasePlayer"){printf("  REAL klass 0x%llx ns=\"%s\"\n",(unsigned long long)K,ns.c_str());real_kl.push_back(K);}
    }
    if(real_kl.empty()){printf("no real klass\n");return 1;}
    uint64_t KL=real_kl[0];
    // 3. objects: [obj]==KL directly (true IL2CPP: object->klass is direct!)
    std::vector<uint64_t> objs;
    for(auto&r:g_rw){uint64_t rs=r.e-r.s;if(rs>512ULL*1024*1024)continue;
        for(uint64_t o=0;o<rs;o+=C){uint64_t tr=std::min<uint64_t>(C,rs-o);mach_vm_size_t got=0;
            if(mach_vm_read_overwrite(g_task,r.s+o,tr,(vm_address_t)buf.data(),&got)!=KERN_SUCCESS)break;
            for(size_t i=0;i+8<=got;i+=8){uint64_t v;memcpy(&v,buf.data()+i,8);
                if(v==KL)objs.push_back(r.s+o+i);}}}
    printf("objects with [obj]==BasePlayer klass: %zu\n",objs.size());
    for(size_t i=0;i<objs.size()&&i<15;i++){
        uint64_t ob=objs[i];
        printf("  obj 0x%llx: +8=0x%llx +0x10=0x%llx", (unsigned long long)ob,
               (unsigned long long)spac(r64(ob+8)),(unsigned long long)spac(r64(ob+0x10)));
        for(int off:{0x1b0,0x290,0x6a8,0x6b8,0x700,0x718,0x7f8}){
            uint64_t s=spac(r64(ob+off));
            if(s>=76561198000000000ULL&&s<76561200000000000ULL)printf(" SID@+0x%x=%llu",off,(unsigned long long)s);
        }
        printf("\n");
    }
    return 0;
}
