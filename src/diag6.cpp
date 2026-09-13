
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
static void enum_rw(){g_rw.clear();mach_vm_address_t a=0;mach_vm_size_t sz;vm_region_basic_info_data_64_t info;mach_msg_type_number_t cnt;mach_port_t obj;
while(true){cnt=VM_REGION_BASIC_INFO_COUNT_64;if(mach_vm_region(g_task,&a,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&cnt,&obj)!=KERN_SUCCESS)break;
if((info.protection&VM_PROT_READ)&&(info.protection&VM_PROT_WRITE))g_rw.push_back({a,a+sz});a+=sz;}}
static pid_t find_rust(){pid_t pids[16384];int n=proc_listpids(PROC_ALL_PIDS,0,pids,sizeof(pids));
for(int i=0;i<n/(int)sizeof(pid_t);i++){if(!pids[i])continue;char path[PROC_PIDPATHINFO_MAXSIZE]={};
if(proc_pidpath(pids[i],path,sizeof(path))>0&&strstr(path,"RustClient"))return pids[i];}return -1;}
static std::string read_cstr(uint64_t p,int max=100){char b[112]={};if(!vp(p)||!rmem(p,b,max))return"";b[max]=0;
for(int i=0;i<max;i++){char c=b[i];if(c==0)return std::string(b,i);if((unsigned char)c<0x20||(unsigned char)c>0x7e)return"";}
return std::string(b);}
// robust klass resolution: obj+0 may be klass (then name at +0x10) OR vtable (then [0]=klass)
static std::string klass_name2(uint64_t obj){
    uint64_t a=spac(r64(obj)); if(!vp(a))return"";
    // case 1: a IS klass
    {uint64_t np=spac(r64(a+0x10)); std::string s=read_cstr(np);
     if(!s.empty()&&s[0]>='A'&&s[0]<='Z')return s;}
    // case 2: a is vtable, klass = [a]
    {uint64_t k=spac(r64(a)); if(!vp(k))return"";
     uint64_t np=spac(r64(k+0x10)); std::string s=read_cstr(np);
     if(!s.empty()&&s[0]>='A'&&s[0]<='Z')return s;}
    return"";
}
int main(){
    const uint64_t SELF=76561198984296471ULL;
    pid_t pid=find_rust(); if(pid<0){printf("no rust\n");return 1;}
    if(task_for_pid(mach_task_self(),pid,&g_task)!=KERN_SUCCESS){printf("tfp fail\n");return 1;}
    enum_rw();
    const size_t C=4*1024*1024; std::vector<uint8_t> buf(C);
    std::vector<uint64_t> addrs;
    for(auto&r:g_rw){uint64_t rs=r.e-r.s;if(rs>512ULL*1024*1024)continue;
        for(uint64_t o=0;o<rs;o+=C){uint64_t tr=std::min<uint64_t>(C,rs-o);mach_vm_size_t got=0;
            if(mach_vm_read_overwrite(g_task,r.s+o,tr,(vm_address_t)buf.data(),&got)!=KERN_SUCCESS)break;
            for(size_t i=0;i+8<=got;i+=8){uint64_t v;memcpy(&v,buf.data()+i,8);
                if(v==SELF)addrs.push_back(r.s+o+i);}}}
    printf("SELF occurrences: %zu\n",addrs.size());
    // classify each occurrence: walk back 0..0x1400, list ALL klass names found (not just nearest)
    std::unordered_map<std::string,int> dist;
    for(size_t ai=0;ai<addrs.size();ai++){
        uint64_t addr=addrs[ai];
        std::unordered_map<std::string,int> seen;
        for(int off=0;off<=0x1400;off+=8){
            uint64_t obj=addr-off; if(!vp(obj))continue;
            std::string kn=klass_name2(obj);
            if(!kn.empty()&&seen.find(kn)==seen.end()){
                seen[kn]=off;
                dist[kn+"@"+std::to_string(off)]++;
            }
        }
        if(ai<3){printf("occ[%zu] @0x%llx names:",ai,(unsigned long long)addr);
            for(auto&[k,o]:seen)printf(" %s@+0x%x",k.c_str(),o);printf("\n");}
    }
    printf("\ndistribution (name@first_offset):\n");
    std::vector<std::pair<std::string,int>> v(dist.begin(),dist.end());
    sort(v.begin(),v.end(),[](auto&a,auto&b){return a.second>b.second;});
    for(int i=0;i<(int)v.size()&&i<40;i++)printf("  %-40s x%d\n",v[i].first.c_str(),v[i].second);
    return 0;
}
