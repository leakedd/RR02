
#include <cstdio>
#include <cstdint>
#include <cstring>
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
    const uint64_t SMIN=76561198000000000ULL,SMAX=76561200000000000ULL;
    pid_t pid=find_rust(); if(pid<0){printf("no rust\n");return 1;}
    if(task_for_pid(mach_task_self(),pid,&g_task)!=KERN_SUCCESS){printf("tfp fail\n");return 1;}
    enum_rw();
    printf("regions=%zu\n",g_rw.size());
    const size_t C=4*1024*1024; std::vector<uint8_t> buf(C);
    std::vector<std::pair<uint64_t,uint64_t>> occ;  // (addr, sid)
    for(auto&r:g_rw){uint64_t rs=r.e-r.s;if(rs>512ULL*1024*1024)continue;
        for(uint64_t o=0;o<rs;o+=C){uint64_t tr=std::min<uint64_t>(C,rs-o);mach_vm_size_t got=0;
            if(mach_vm_read_overwrite(g_task,r.s+o,tr,(vm_address_t)buf.data(),&got)!=KERN_SUCCESS)break;
            for(size_t i=0;i+8<=got;i+=8){uint64_t v;memcpy(&v,buf.data()+i,8);
                if(v>=SMIN&&v<SMAX)occ.push_back({r.s+o+i,v});}}}
    printf("occurrences=%zu\n",occ.size());
    std::unordered_map<uint64_t,int> sidc;
    for(auto&[a,s]:occ)sidc[s]++;
    printf("unique=%zu\n",sidc.size());
    // check SELF_SID presence
    const uint64_t SELF=76561198984296471ULL;
    printf("SELF_SID occurrences: %d\n", sidc.count(SELF)?sidc[SELF]:0);
    // classify: for up to 400 occ, walk back to find nearest named klass
    std::unordered_map<std::string,int> klass_count;
    std::unordered_map<uint64_t, std::vector<std::pair<uint64_t,std::string>>> sid_klass;
    int nchk=0;
    for(auto&[addr,s]:occ){
        if(nchk++>=400)break;
        for(int off=0;off<=0x1400;off+=8){
            uint64_t obj=addr-off; if(!vp(obj))continue;
            std::string kn=klass_name(obj); if(kn.empty())continue;
            if(kn[0]<'A'||kn[0]>'Z')continue;
            klass_count[kn]++;
            if(kn.find("Player")!=std::string::npos) sid_klass[s].push_back({obj,kn});
            break;
        }
    }
    printf("\nklass distribution near SID occurrences:\n");
    std::vector<std::pair<std::string,int>> kc(klass_count.begin(),klass_count.end());
    std::sort(kc.begin(),kc.end(),[](auto&a,auto&b){return a.second>b.second;});
    for(int i=0;i<(int)kc.size()&&i<30;i++)printf("  %-32s x%d\n",kc[i].first.c_str(),kc[i].second);
    printf("\nPlayer-ish klass per SID:\n");
    for(auto&[s,v]:sid_klass){
        if(sidc[s]<3)continue;   // only SIDs seen 3+ times
        std::unordered_map<std::string,int> kk;
        for(auto&[o,k]:v)kk[k]++;
        printf("  SID=%llu (x%d):",(unsigned long long)s,sidc[s]);
        for(auto&[k,c]:kk)printf(" %s x%d",k.c_str(),c);
        printf("\n");
    }
    return 0;
}
