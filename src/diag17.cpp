
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>
#include <map>
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
static float d3(const V3&a,const V3&b){float dx=a.x-b.x,dy=a.y-b.y,dz=a.z-b.z;return sqrtf(dx*dx+dy*dy+dz*dz);}
struct Snap{uint64_t addr; V3 v;};
static std::vector<Snap> g_snap;   // all world float3 in RW memory
static void full_scan(){
    g_snap.clear();
    const size_t C=4*1024*1024; std::vector<uint8_t> buf(C);
    for(auto&r:g_rw){uint64_t rs=r.e-r.s;if(rs>512ULL*1024*1024)continue;
        for(uint64_t o=0;o<rs;o+=C){uint64_t tr=std::min<uint64_t>(C,rs-o);mach_vm_size_t got=0;
            if(mach_vm_read_overwrite(g_task,r.s+o,tr,(vm_address_t)buf.data(),&got)!=KERN_SUCCESS)break;
            for(size_t i=0;i+12<=got;i+=4){
                V3 v;memcpy(&v.x,buf.data()+i,4);memcpy(&v.y,buf.data()+i+4,4);memcpy(&v.z,buf.data()+i+8,4);
                if(vw(v))g_snap.push_back({r.s+o+i,v});
            }}}}
int main(int argc,char**argv){
    int ROUNDS=argc>1?atoi(argv[1]):6;
    pid_t pid=find_rust(); if(pid<0){printf("no rust\n");return 1;}
    if(task_for_pid(mach_task_self(),pid,&g_task)!=KERN_SUCCESS){printf("tfp fail\n");return 1;}
    enum_rw();
    printf("full scan 1...\n");full_scan();
    printf("  %zu world float3\n",g_snap.size());
    std::map<uint64_t,int> hits;      // addr -> rounds moved
    std::map<uint64_t,V3> last;
    for(int round=0;round<ROUNDS;round++){
        sleep(3);
        std::vector<Snap> s2; 
        // rescan but reuse g_snap positions for matching by ADDR (same address, compare values)
        std::unordered_map<uint64_t,V3> m1;
        for(auto&s:g_snap)m1[s.addr]=s.v;
        full_scan();
        int rh=0;
        for(auto&s:g_snap){
            auto it=m1.find(s.addr);
            if(it==m1.end())continue;
            float d=d3(it->second,s.v);
            if(d<0.4f||d>80.0f)continue;
            hits[s.addr]++;
            last[s.addr]=s.v;
            rh++;
        }
        printf("  round %d: %d movers (total %zu world float3)\n",round,rh,g_snap.size());fflush(stdout);
    }
    // report: movers sorted by rounds desc
    printf("\n=== consistent movers (>= %d rounds) ===\n",ROUNDS-1);
    std::vector<std::pair<uint64_t,int>> v(hits.begin(),hits.end());
    std::sort(v.begin(),v.end(),[](auto&a,auto&b){return a.second>b.second;});
    int shown=0;
    for(auto&[a,c]:v){
        if(c<ROUNDS-1)break;
        V3&L=last[a];
        printf("  0x%llx rounds=%d pos=(%.1f, %.1f, %.1f)\n",(unsigned long long)a,c,L.x,L.y,L.z);
        if(shown++>30)break;
    }
    return 0;
}
