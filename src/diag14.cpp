
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>
#include <map>
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
if(v.x<-4200||v.x>4200||v.z<-4200||v.z>4200)return false;if(v.y<-100||v.y>3000)return false;
if(v.x*v.x+v.z*v.z<4.0f)return false;return true;}   // reject near-origin
static float d3(const V3&a,const V3&b){float dx=a.x-b.x,dy=a.y-b.y,dz=a.z-b.z;return sqrtf(dx*dx+dy*dy+dz*dz);}
int main(int argc,char**argv){
    const uint64_t SMIN=76561198000000000ULL,SMAX=76561200000000000ULL;
    const uint64_t SELF=76561198984296471ULL;
    int ROUNDS=argc>1?atoi(argv[1]):10;
    pid_t pid=find_rust(); if(pid<0){printf("no rust\n");return 1;}
    if(task_for_pid(mach_task_self(),pid,&g_task)!=KERN_SUCCESS){printf("tfp fail\n");return 1;}
    enum_rw();
    // 1. all SID addrs
    const size_t C=4*1024*1024; std::vector<uint8_t> buf(C);
    std::map<uint64_t,std::vector<uint64_t>> occ;
    for(auto&r:g_rw){uint64_t rs=r.e-r.s;if(rs>512ULL*1024*1024)continue;
        for(uint64_t o=0;o<rs;o+=C){uint64_t tr=std::min<uint64_t>(C,rs-o);mach_vm_size_t got=0;
            if(mach_vm_read_overwrite(g_task,r.s+o,tr,(vm_address_t)buf.data(),&got)!=KERN_SUCCESS)break;
            for(size_t i=0;i+8<=got;i+=8){uint64_t v;memcpy(&v,buf.data()+i,8);
                if(v>=SMIN&&v<SMAX)occ[v].push_back(r.s+o+i);}}}
    printf("SIDs: %zu\n",occ.size());
    // 2. containers: obj = sid_addr - 0x1b0 (both), scan 0x2000 bytes each for world float3.
    // Structure: cont_addr -> (sid, off). Delta over rounds.
    struct Cand{uint64_t cont; int off; uint64_t sid;};
    std::vector<Cand> cands;
    for(auto&[sid,addrs]:occ){
        for(uint64_t sa:addrs){
            for(int pre:{0x1b0}){
                uint64_t cont=sa-pre;
                if(!vp(cont+0x2000))continue;
                uint8_t b[0x2000];
                if(!rmem(cont,b,0x2000))continue;
                for(int f=0;f+12<=0x2000;f+=4){
                    V3 v;memcpy(&v.x,b+f,4);memcpy(&v.y,b+f+4,4);memcpy(&v.z,b+f+8,4);
                    if(vw(v))cands.push_back({cont,f,sid});
                }
            }
        }
    }
    printf("initial float3 candidates in containers: %zu\n",cands.size());
    // 3. delta rounds on the unique (cont,off) pairs
    std::map<std::pair<uint64_t,int>,uint64_t> key_sid;
    for(auto&c:cands)key_sid[{c.cont,c.off}]=c.sid;
    printf("unique (cont,off): %zu\n",key_sid.size());
    std::map<std::pair<uint64_t,int>,int> hits;
    std::map<std::pair<uint64_t,int>,V3> last;
    for(int round=0;round<ROUNDS;round++){
        std::map<std::pair<uint64_t,int>,V3> s1;
        for(auto&[k,sid]:key_sid){
            V3 v;
            if(rmem(k.first+k.second,&v,12)&&vw(v))s1[k]=v;
        }
        sleep(3);
        int rh=0;
        for(auto&[k,sid]:key_sid){
            V3 v;
            if(!rmem(k.first+k.second,&v,12)||!vw(v))continue;
            auto it=s1.find(k);
            if(it==s1.end())continue;
            float d=d3(it->second,v);
            if(d<0.15f||d>300.0f)continue;
            hits[k]++;
            last[k]=v;
            rh++;
        }
        printf("  round %d: %d movers\n",round,rh);fflush(stdout);
    }
    printf("\n=== LIVE positions (moved >=3 rounds) ===\n");
    std::vector<std::pair<std::pair<uint64_t,int>,int>> v(hits.begin(),hits.end());
    std::sort(v.begin(),v.end(),[](auto&a,auto&b){return a.second>b.second;});
    for(auto&[k,c]:v){
        if(c<3)continue;
        V3&L=last[k];
        uint64_t sid=key_sid[k];
        printf("  %sSID=%llu cont=0x%llx off=+0x%x pos=(%.1f, %.1f, %.1f) rounds=%d\n",
            sid==SELF?"★":" ",(unsigned long long)sid,(unsigned long long)k.first,k.second,L.x,L.y,L.z,c);
    }
    return 0;
}
