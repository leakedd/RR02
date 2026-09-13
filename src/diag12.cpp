
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>
#include <unordered_map>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>
static task_t g_task;
static bool rmem(uint64_t a, void* b, size_t s){vm_size_t g=0;return vm_read_overwrite(g_task,(vm_address_t)a,s,(vm_address_t)b,&g)==KERN_SUCCESS&&(size_t)g==s;}
static uint64_t spac(uint64_t p){return p & 0x0000FFFFFFFFFFFFULL;}
static bool vp(uint64_t p){uint64_t s=spac(p);return s>0x10000ULL&&s<0x7FFFFFFFFFFFULL;}
struct Rg{uint64_t s,e;};static std::vector<Rg> g_rw;
static void enum_rw(){g_rw.clear();mach_vm_address_t a=0;mach_vm_size_t sz;vm_region_basic_info_data_64_t info;mach_msg_type_number_t cnt;mach_port_t obj;
while(true){cnt=VM_REGION_BASIC_INFO_COUNT_64;if(mach_vm_region(g_task,&a,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&cnt,&obj)!=KERN_SUCCESS)break;
if((info.protection&VM_PROT_READ)&&(info.protection&VM_PROT_WRITE))g_rw.push_back({a,a+sz});a+=sz;}}
static pid_t find_rust(){pid_t pids[16384];int n=proc_listpids(PROC_ALL_PIDS,0,pids,sizeof(pids));
for(int i=0;i<n/(int)sizeof(pid_t);i++){if(!pids[i])continue;char path[PROC_PIDPATHINFO_MAXSIZE]={};
if(proc_pidpath(pids[i],path,sizeof(path))>0&&strstr(path,"RustClient"))return pids[i];}return -1;}
struct V3{float x,y,z;};
static bool vw(const V3&v){if(!std::isfinite(v.x)||!std::isfinite(v.y)||!std::isfinite(v.z))return false;
if(v.x<-4200||v.x>4200||v.z<-4200||v.z>4200)return false;if(v.y<-100||v.y>3000)return false;return true;}
int main(){
    const uint64_t SELF=76561198984296471ULL;
    const uint64_t SMIN=76561198000000000ULL,SMAX=76561200000000000ULL;
    pid_t pid=find_rust(); if(pid<0){printf("no rust\n");return 1;}
    if(task_for_pid(mach_task_self(),pid,&g_task)!=KERN_SUCCESS){printf("tfp fail\n");return 1;}
    enum_rw();
    // snapshot 1: all SID occurrences
    const size_t C=4*1024*1024; std::vector<uint8_t> buf(C);
    std::unordered_map<uint64_t,std::vector<uint64_t>> occ;   // sid -> addrs
    for(auto&r:g_rw){uint64_t rs=r.e-r.s;if(rs>512ULL*1024*1024)continue;
        for(uint64_t o=0;o<rs;o+=C){uint64_t tr=std::min<uint64_t>(C,rs-o);mach_vm_size_t got=0;
            if(mach_vm_read_overwrite(g_task,r.s+o,tr,(vm_address_t)buf.data(),&got)!=KERN_SUCCESS)break;
            for(size_t i=0;i+8<=got;i+=8){uint64_t v;memcpy(&v,buf.data()+i,8);
                if(v>=SMIN&&v<SMAX)occ[v].push_back(r.s+o+i);}}}
    printf("unique SIDs: %zu\n",occ.size());
    // For each SID with >=3 occurrences, test container hypothesis: sid_addr - 0x1b0 = obj,
    // pos @ obj+0x1168. Validate V3.
    printf("\nSID containers (obj=sidaddr-0x1b0, pos@+0x1168):\n");
    int nself=0;
    for(auto&[sid,addrs]:occ){
        if(addrs.size()<2)continue;
        for(uint64_t sa:addrs){
            uint64_t obj=sa-0x1b0;
            if(!vp(obj+0x1168))continue;
            V3 pos;
            if(!rmem(obj+0x1168,&pos,12))continue;
            if(!vw(pos))continue;
            bool me=(sid==SELF);
            if(me)nself++;
            if(me||addrs.size()>=3)
                printf("  %sSID=%llu occ=%zu obj=0x%llx pos=(%.1f, %.1f, %.1f)\n",
                    me?"★":" ",(unsigned long long)sid,addrs.size(),(unsigned long long)obj,pos.x,pos.y,pos.z);
        }
    }
    printf("self candidates with valid pos: %d\n",nself);
    // ALSO test alternative: obj = sa - 0x290 (radar_new found sid_off=+0x290 for PlayerCorpse)
    printf("\nalt containers (obj=sidaddr-0x290, pos@+0x1168):\n");
    for(auto&[sid,addrs]:occ){
        if(addrs.size()<2)continue;
        for(uint64_t sa:addrs){
            uint64_t obj=sa-0x290;
            if(!vp(obj+0x1168))continue;
            V3 pos;
            if(!rmem(obj+0x1168,&pos,12))continue;
            if(!vw(pos))continue;
            if(sid==SELF)printf("  ★SID=%llu occ=%zu obj=0x%llx pos=(%.1f, %.1f, %.1f)\n",
                (unsigned long long)sid,addrs.size(),(unsigned long long)obj,pos.x,pos.y,pos.z);
        }
    }
    return 0;
}
