// hunt_pm4 — signature FORTE d'un PlayerModel :
//   +0x2F8 Vector3 position, +0x304 Vector3, +0x310 Vector3,
//   +0x328 Quaternion unitaire, +0x338 Quaternion unitaire, +0x35C/+0x368 Vector3
// puis regroupement des objets par pointeur situé en tête d'objet (obj+0x0) pour retrouver la vraie classe.
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>
#include <map>
#include <cmath>
#include <algorithm>
static task_t T=MACH_PORT_NULL;
static bool rd(uint64_t a,void*b,size_t n){mach_vm_size_t g=0;return mach_vm_read_overwrite(T,a,n,(mach_vm_address_t)b,&g)==KERN_SUCCESS&&g==n;}
static uint64_t r64(uint64_t a){uint64_t v=0;rd(a,&v,8);return v;}
static inline bool vec3(const float*v){return std::isfinite(v[0])&&std::isfinite(v[1])&&std::isfinite(v[2])
    &&fabsf(v[0])<5000&&fabsf(v[2])<5000&&v[1]>-200&&v[1]<1200&&(fabsf(v[0])>3||fabsf(v[2])>3);}
static inline bool quat(const float*q){float n=q[0]*q[0]+q[1]*q[1]+q[2]*q[2]+q[3]*q[3];
    return std::isfinite(n)&&fabsf(n-1.0f)<0.02f;}
static inline float f32(const uint8_t*b,size_t o){float v;memcpy(&v,b+o,4);return v;}
static inline bool vec3b(const uint8_t*b,size_t o){float v[3]={f32(b,o),f32(b,o+4),f32(b,o+8)};return vec3(v);}
static inline bool quatb(const uint8_t*b,size_t o){float q[4]={f32(b,o),f32(b,o+4),f32(b,o+8),f32(b,o+12)};return quat(q);}
int main(){
    int bytes=proc_listpids(PROC_ALL_PIDS,0,nullptr,0);
    std::vector<pid_t> ps(bytes/4+256);bytes=proc_listpids(PROC_ALL_PIDS,0,ps.data(),ps.size()*4);
    pid_t pid=0;for(int i=0;i<bytes/4;i++){char p[PROC_PIDPATHINFO_MAXSIZE]={};if(proc_pidpath(ps[i],p,sizeof p)>0&&strstr(p,"/RustClient.app/Contents/MacOS/Rust")){pid=ps[i];break;}}
    if(task_for_pid(mach_task_self(),pid,&T)!=KERN_SUCCESS){printf("TFP_FAIL\n");return 1;}
    std::map<uint64_t,std::vector<std::pair<float,float>>> groups;
    long long hits=0;
    mach_vm_address_t addr=0;mach_vm_size_t size=0;vm_region_basic_info_data_64_t info;mach_msg_type_number_t ic=VM_REGION_BASIC_INFO_COUNT_64;mach_port_t obj=0;
    const size_t CH=8*1024*1024;std::vector<uint8_t> buf(CH+512);
    while(1){
        kern_return_t kr=mach_vm_region(T,&addr,&size,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&ic,&obj);
        if(kr!=KERN_SUCCESS)break;
        uint64_t cur=addr,left=size;addr+=size;
        if(!(info.protection&VM_PROT_WRITE)||size<1024*1024)continue;
        while(left>0){
            size_t n=(left<CH)?(size_t)left:CH;mach_vm_size_t got=0;
            if(mach_vm_read_overwrite(T,cur,n,(mach_vm_address_t)buf.data(),&got)==KERN_SUCCESS&&got>0x380){
                for(size_t o=0;o+0x380<=got;o+=8){
                    if(!vec3b(buf.data(),o+0x2F8))continue;
                    if(!vec3b(buf.data(),o+0x304))continue;
                    if(!vec3b(buf.data(),o+0x310))continue;
                    if(!quatb(buf.data(),o+0x328))continue;
                    if(!quatb(buf.data(),o+0x338))continue;
                    if(!vec3b(buf.data(),o+0x35C)&&!vec3b(buf.data(),o+0x368))continue;
                    uint64_t oa=cur+o;uint64_t k=*(uint64_t*)(buf.data()+o);
                    if(k<0x1000000||k>0x800000000000ULL)continue;
                    hits++;
                    auto&g=groups[k];if(g.size()<6)g.push_back({f32(buf.data(),o+0x2F8),f32(buf.data(),o+0x2F8+8)});
                }
            }
            if(left<=n)break;cur+=n;left-=n;
        }
    }
    std::vector<std::pair<int,uint64_t>> v;
    for(auto&kv:groups)v.push_back({(int)kv.second.size(),kv.first});
    std::sort(v.rbegin(),v.rend());
    printf("objets signature-forte=%lld  classes distinctes=%zu\n",hits,groups.size());
    int shown=0;
    for(auto&p:v){
        if(p.first<3)continue;
        char nm[128]={};uint64_t np=r64(p.second+0x20);
        if(!(np&&rd(np,nm,100)))nm[0]=0;
        printf("  tete=0x%-12llx n=%-5d name@+0x20='%s'  pos:",(unsigned long long)p.second,p.first,nm);
        for(auto&q:groups[p.second])printf(" (%.1f,%.1f)",q.first,q.second);
        printf("\n");
        if(++shown>=12)break;
    }
    return 0;
}
