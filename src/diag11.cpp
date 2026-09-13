
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
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
int main(){
    pid_t pid=find_rust(); if(pid<0){printf("no rust\n");return 1;}
    if(task_for_pid(mach_task_self(),pid,&g_task)!=KERN_SUCCESS){printf("tfp fail\n");return 1;}
    enum_all();
    const uint64_t KLs[2]={0x127cbde40ULL,0x1020794c0ULL};
    const size_t C=4*1024*1024; std::vector<uint8_t> buf(C);
    for(int ki=0;ki<2;ki++){
        uint64_t KL=KLs[ki];
        printf("=== klass 0x%llx ===\n",(unsigned long long)KL);
        std::vector<uint64_t> hits; std::vector<uint64_t> big_regions_skipped;
        for(auto&r:g_rw){uint64_t rs=r.e-r.s;
            for(uint64_t o=0;o<rs;o+=C){uint64_t tr=std::min<uint64_t>(C,rs-o);mach_vm_size_t got=0;
                if(mach_vm_read_overwrite(g_task,r.s+o,tr,(vm_address_t)buf.data(),&got)!=KERN_SUCCESS)break;
                for(size_t i=0;i+8<=got;i+=8){uint64_t v;memcpy(&v,buf.data()+i,8);
                    if(v==KL)hits.push_back(r.s+o+i);}}}
        printf("  qword==klass hits: %zu\n",hits.size());
        int shown=0;
        for(uint64_t h:hits){
            if(shown++>=10)break;
            // is this a vtable[0] (followed by method ptrs) or an object slot?
            uint64_t nxt=spac(r64(h+8));
            uint64_t prev=spac(r64(h-8));
            printf("   @0x%llx prev=0x%llx next=0x%llx\n",(unsigned long long)h,(unsigned long long)prev,(unsigned long long)nxt);
        }
        // If hits are vtables: objects point at vtable addr (or vtable+off). For each hit vtable,
        // scan a few regions for pointers to it? too slow. Instead sample: read a known player-ish
        // region? Let's instead scan for objects whose [obj] points WITHIN [hit-0x100, hit+0x1000]
        // — vtables are arrays; object->vtable points at the class's method array start (hit).
        if(!hits.empty()){
            std::vector<uint64_t> objs_found;
            for(auto&r:g_rw){uint64_t rs=r.e-r.s;
                for(uint64_t o=0;o<rs;o+=C){uint64_t tr=std::min<uint64_t>(C,rs-o);mach_vm_size_t got=0;
                    if(mach_vm_read_overwrite(g_task,r.s+o,tr,(vm_address_t)buf.data(),&got)!=KERN_SUCCESS)break;
                    for(size_t i=0;i+8<=got;i+=8){uint64_t v;memcpy(&v,buf.data()+i,8);v=spac(v);
                        if(v>hits[0]-0x40&&v<hits[0]+0x2000)objs_found.push_back(r.s+o+i);}}}
            printf("  objects pointing near vtable: %zu\n",objs_found.size());
            for(size_t i=0;i<objs_found.size()&&i<12;i++){
                uint64_t ob=objs_found[i];
                uint64_t slot=spac(r64(ob));
                printf("   obj 0x%llx ->[0]=0x%llx (delta from vt0=%lld)\n",(unsigned long long)ob,(unsigned long long)slot,(long long)(slot-hits[0]));
                for(int off:{0x1b0,0x290,0x6a8,0x6b8,0x700,0x718,0x7f8}){
                    uint64_t s=spac(r64(ob+off));
                    if(s>=76561198000000000ULL&&s<76561200000000000ULL)printf("      SID@+0x%x=%llu\n",off,(unsigned long long)s);
                }
            }
        }
    }
    return 0;
}
