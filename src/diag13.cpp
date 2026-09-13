
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>
#include <map>
#include <set>
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
static float d3(const V3&a,const V3&b){float dx=a.x-b.x,dy=a.y-b.y,dz=a.z-b.z;return sqrtf(dx*dx+dy*dy+dz*dz);}
struct Hit{int rel; V3 a,b;};   // rel = offset from sid addr
int main(int argc,char**argv){
    const uint64_t SELF=76561198984296471ULL;
    const uint64_t SMIN=76561198000000000ULL,SMAX=76561200000000000ULL;
    int ROUNDS=argc>1?atoi(argv[1]):8;
    pid_t pid=find_rust(); if(pid<0){printf("no rust\n");return 1;}
    if(task_for_pid(mach_task_self(),pid,&g_task)!=KERN_SUCCESS){printf("tfp fail\n");return 1;}
    enum_rw();
    // find SELF SID addrs
    const size_t C=4*1024*1024; std::vector<uint8_t> buf(C);
    std::vector<uint64_t> self_addrs;
    std::vector<uint64_t> other;  // (sid<<16|idx) too big; count only
    std::map<uint64_t,int> occ_count;
    for(auto&r:g_rw){uint64_t rs=r.e-r.s;if(rs>512ULL*1024*1024)continue;
        for(uint64_t o=0;o<rs;o+=C){uint64_t tr=std::min<uint64_t>(C,rs-o);mach_vm_size_t got=0;
            if(mach_vm_read_overwrite(g_task,r.s+o,tr,(vm_address_t)buf.data(),&got)!=KERN_SUCCESS)break;
            for(size_t i=0;i+8<=got;i+=8){uint64_t v;memcpy(&v,buf.data()+i,8);
                if(v>=SMIN&&v<SMAX){occ_count[v]++;if(v==SELF)self_addrs.push_back(r.s+o+i);}}}}
    printf("SELF addrs: %zu, unique SIDs: %zu\n",self_addrs.size(),occ_count.size());
    // Window: scan +/-0x400 around each self addr. Delta over rounds.
    const int WIN=0x400;
    int nA=self_addrs.size();
    std::map<int,int> hits;          // rel offset -> rounds moved
    std::map<int,V3> lastpos;
    for(int round=0;round<ROUNDS;round++){
        // snapshot 1
        std::vector<std::map<int,V3>> s1(nA);
        for(int i=0;i<nA;i++){
            std::vector<uint8_t> b(2*WIN);
            if(!rmem(self_addrs[i]-WIN,b.data(),2*WIN))continue;
            for(int f=0;f+12<=2*WIN;f+=4){
                V3 v;memcpy(&v.x,b.data()+f,4);memcpy(&v.y,b.data()+f+4,4);memcpy(&v.z,b.data()+f+8,4);
                if(vw(v))s1[i][f-WIN]=v;
            }
        }
        sleep(3);
        int rh=0;
        for(int i=0;i<nA;i++){
            std::vector<uint8_t> b(2*WIN);
            if(!rmem(self_addrs[i]-WIN,b.data(),2*WIN))continue;
            for(int f=0;f+12<=2*WIN;f+=4){
                V3 v;memcpy(&v.x,b.data()+f,4);memcpy(&v.y,b.data()+f+4,4);memcpy(&v.z,b.data()+f+8,4);
                int rel=f-WIN;
                auto it=s1[i].find(rel);
                if(it==s1[i].end())continue;
                float d=d3(it->second,v);
                if(d<0.2f||d>300.0f)continue;
                hits[rel]++;
                lastpos[rel]=v;
                rh++;
            }
        }
        printf("  round %d: %d moving\n",round,rh);fflush(stdout);
    }
    printf("\nmoving rel-offsets (>=2 rounds):\n");
    std::vector<std::pair<int,int>> v(hits.begin(),hits.end());
    std::sort(v.begin(),v.end(),[](auto&a,auto&b){return a.second>b.second;});
    for(auto&[rel,c]:v){
        if(c<2)continue;
        V3&L=lastpos[rel];
        printf("  rel=%+d (0x%x): %d rounds, pos=(%.1f, %.1f, %.1f)\n",rel,rel,c,L.x,L.y,L.z);
    }
    return 0;
}
