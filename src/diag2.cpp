
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>
#include <unordered_map>
#include <algorithm>
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
static std::string klass_name(uint64_t obj){uint64_t vt=spac(r64(obj));if(!vp(vt))return"";
uint64_t kl=spac(r64(vt));if(!vp(kl))return"";uint64_t np=spac(r64(kl+0x10));if(!vp(np))return"";
char buf[128]={};if(!rmem(np,buf,127))return"";return std::string(buf);}
int main(){
    const uint64_t SMIN = 76561198000000000ULL, SMAX = 76561200000000000ULL;
    printf("SMIN=%llu\n",(unsigned long long)SMIN);
    pid_t pid=find_rust(); if(pid<0){printf("no rust\n");return 1;}
    if(task_for_pid(mach_task_self(),pid,&g_task)!=KERN_SUCCESS){printf("tfp fail\n");return 1;}
    enum_rw();
    const size_t C=4*1024*1024; std::vector<uint8_t> buf(C);
    std::unordered_map<uint64_t,int> sid_count;
    int total=0;
    for(auto&r:g_rw){uint64_t rs=r.e-r.s;if(rs>512ULL*1024*1024)continue;
        for(uint64_t o=0;o<rs;o+=C){uint64_t tr=std::min<uint64_t>(C,rs-o);mach_vm_size_t got=0;
            if(mach_vm_read_overwrite(g_task,r.s+o,tr,(vm_address_t)buf.data(),&got)!=KERN_SUCCESS)break;
            for(size_t i=0;i+8<=got;i+=8){uint64_t v;memcpy(&v,buf.data()+i,8);
                if(v>=SMIN&&v<SMAX){sid_count[v]++;total++;}}}}
    printf("total=%d unique=%zu\n",total,sid_count.size());
    // Verify every stored SID actually satisfies the range
    int bad=0;
    for(auto&[s,c]:sid_count) if(!(s>=SMIN&&s<SMAX)) bad++;
    printf("bad range entries: %d\n", bad);
    // print top 30 by count
    std::vector<std::pair<uint64_t,int>> v(sid_count.begin(),sid_count.end());
    std::sort(v.begin(),v.end(),[](auto&a,auto&b){return a.second>b.second;});
    for(int i=0;i<(int)v.size()&&i<30;i++) printf("  SID=%llu x%d\n",(unsigned long long)v[i].first,v[i].second);
    // For the top SIDs, find klass-named objects
    printf("\n--- obj discovery for top SIDs ---\n");
    int checked=0;
    std::unordered_map<uint64_t,std::vector<std::pair<uint64_t,std::string>>> sid_objs;
    for(auto&[s,c]:v){
        if(checked++>25)break;
        // find occurrences of this SID again (scan)
        // reuse: scan regions for exact value s
        std::vector<uint64_t> addrs;
        for(auto&r:g_rw){uint64_t rs=r.e-r.s;if(rs>512ULL*1024*1024)continue;
            for(uint64_t o=0;o<rs;o+=C){uint64_t tr=std::min<uint64_t>(C,rs-o);mach_vm_size_t got=0;
                if(mach_vm_read_overwrite(g_task,r.s+o,tr,(vm_address_t)buf.data(),&got)!=KERN_SUCCESS)break;
                for(size_t i=0;i+8<=got;i+=8){uint64_t vv;memcpy(&vv,buf.data()+i,8);
                    if(vv==s)addrs.push_back(r.s+o+i);}}}
        for(uint64_t addr:addrs){
            for(int off=0;off<=0x1400;off+=8){
                uint64_t obj=addr-off; if(!vp(obj))continue;
                std::string kn=klass_name(obj); if(kn.empty())continue;
                if(kn[0]<'A'||kn[0]>'Z')continue;
                if(kn.find("Player")!=std::string::npos||kn.find("player")!=std::string::npos)
                    sid_objs[s].push_back({obj,kn});
                break;
            }
        }
    }
    for(auto&[s,objs]:sid_objs){
        printf("SID=%llu (%zu player-ish):\n",(unsigned long long)s,objs.size());
        std::unordered_map<std::string,int> kcnt;
        for(auto&[o,k]:objs)kcnt[k]++;
        for(auto&[k,c]:kcnt)printf("    %s x%d\n",k.c_str(),c);
        // print first object addr per klass
        std::unordered_map<std::string,uint64_t> first;
        for(auto&[o,k]:objs)if(!first.count(k))first[k]=o;
        for(auto&[k,o]:first)printf("      e.g. 0x%llx\n",(unsigned long long)o);
    }
    return 0;
}
