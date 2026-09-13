
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
static std::string klass_name(uint64_t obj){
    uint64_t a=spac(r64(obj)); if(!vp(a))return"";
    {uint64_t np=spac(r64(a+0x10)); std::string s=read_cstr(np); if(!s.empty()&&s[0]>='A'&&s[0]<='Z')return s;}
    {uint64_t k=spac(r64(a)); if(!vp(k))return"";
     uint64_t np=spac(r64(k+0x10)); std::string s=read_cstr(np); if(!s.empty()&&s[0]>='A'&&s[0]<='Z')return s;}
    return"";
}
struct V3{float x,y,z;};
static bool vw(const V3&v){if(!std::isfinite(v.x)||!std::isfinite(v.y)||!std::isfinite(v.z))return false;
if(v.x<-4200||v.x>4200||v.z<-4200||v.z>4200)return false;if(v.y<-100||v.y>3000)return false;
if(fabs(v.x)<0.5f&&fabs(v.z)<0.5f)return false;return true;}
int main(){
    const uint64_t SMIN=76561198000000000ULL,SMAX=76561200000000000ULL;
    const uint64_t SELF=76561198984296471ULL;
    pid_t pid=find_rust(); if(pid<0){printf("no rust\n");return 1;}
    if(task_for_pid(mach_task_self(),pid,&g_task)!=KERN_SUCCESS){printf("tfp fail\n");return 1;}
    enum_rw();
    // find ALL SID addrs; for each, compute obj=addr-0x290 (found klass PlayerCorpse) and obj=addr-0x1b0;
    // read klass name of obj; if name contains "Player", test chains.
    const size_t C=4*1024*1024; std::vector<uint8_t> buf(C);
    std::map<uint64_t,std::vector<uint64_t>> occ;
    for(auto&r:g_rw){uint64_t rs=r.e-r.s;if(rs>512ULL*1024*1024)continue;
        for(uint64_t o=0;o<rs;o+=C){uint64_t tr=std::min<uint64_t>(C,rs-o);mach_vm_size_t got=0;
            if(mach_vm_read_overwrite(g_task,r.s+o,tr,(vm_address_t)buf.data(),&got)!=KERN_SUCCESS)break;
            for(size_t i=0;i+8<=got;i+=8){uint64_t v;memcpy(&v,buf.data()+i,8);
                if(v>=SMIN&&v<SMAX)occ[v].push_back(r.s+o+i);}}}
    printf("SIDs: %zu\n",occ.size());
    // Build candidate objects with Player-ish klass
    std::map<uint64_t,std::vector<uint64_t>> sid_objs;   // sid -> obj addrs
    for(auto&[sid,addrs]:occ){
        for(uint64_t sa:addrs){
            for(int pre:{0x290,0x1b0,0x130,0x6a8,0x6b8,0x700,0x718,0x7f8}){
                uint64_t obj=sa-pre;
                if(!vp(obj))continue;
                std::string kn=klass_name(obj);
                if(kn.find("Player")==std::string::npos)continue;
                // dedup
                bool dup=false;for(uint64_t o:sid_objs[sid])if(o==obj)dup=true;
                if(!dup)sid_objs[sid].push_back(obj);
            }
        }
    }
    printf("\nPlayer-ish objects:\n");
    for(auto&[sid,objs]:sid_objs){
        printf("%s SID=%llu:\n",sid==SELF?"★":" ",(unsigned long long)sid);
        for(uint64_t obj:objs){
            std::string kn=klass_name(obj);
            printf("   obj 0x%llx klass=%s\n",(unsigned long long)obj,kn.c_str());
            // test chains
            for(int poff:{0x260,0x258,0x268,0x270}){
                uint64_t p=spac(r64(obj+poff));
                if(!vp(p))continue;
                for(int fpoff:{0x1a0,0x198,0x1a8,0x1b0,0x90,0x88,0x98}){
                    V3 v;
                    if(!rmem(p+fpoff,&v,12))continue;
                    if(vw(v))printf("      chain obj+0x%x -> +0x%x: (%.1f, %.1f, %.1f)\n",poff,fpoff,v.x,v.y,v.z);
                }
            }
            // direct float3 in object
            uint8_t b[0x2000];
            if(rmem(obj,b,0x2000)){
                for(int f=0x100;f+12<=0x2000;f+=4){
                    V3 v;memcpy(&v.x,b+f,4);memcpy(&v.y,b+f+4,4);memcpy(&v.z,b+f+8,4);
                    if(vw(v))printf("      inline +0x%x: (%.1f, %.1f, %.1f)\n",f,v.x,v.y,v.z);
                }
            }
        }
    }
    return 0;
}
