
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
static void enum_rw(){g_rw.clear();mach_vm_address_t a=0;mach_vm_size_t sz;vm_region_basic_info_data_64_t info;mach_msg_type_number_t cnt;mach_port_t obj;
while(true){cnt=VM_REGION_BASIC_INFO_COUNT_64;if(mach_vm_region(g_task,&a,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&cnt,&obj)!=KERN_SUCCESS)break;
if((info.protection&VM_PROT_READ)&&(info.protection&VM_PROT_WRITE))g_rw.push_back({a,a+sz});a+=sz;}}
static pid_t find_rust(){pid_t pids[16384];int n=proc_listpids(PROC_ALL_PIDS,0,pids,sizeof(pids));
for(int i=0;i<n/(int)sizeof(pid_t);i++){if(!pids[i])continue;char path[PROC_PIDPATHINFO_MAXSIZE]={};
if(proc_pidpath(pids[i],path,sizeof(path))>0&&strstr(path,"RustClient"))return pids[i];}return -1;}
static std::string read_cstr(uint64_t p,int max=127){char b[128]={};if(!vp(p)||!rmem(p,b,max))return"";b[max]=0;return std::string(b);}
// dump klass and find ASCII strings among its first 0x100 bytes' pointers
static void dump_klass(uint64_t obj, const char* tag){
    uint64_t vt=spac(r64(obj));
    uint64_t kl=spac(r64(vt));
    printf("== %s: obj=0x%llx vt=0x%llx klass=0x%llx\n",tag,(unsigned long long)obj,(unsigned long long)vt,(unsigned long long)kl);
    if(!vp(kl)){printf("   klass invalid\n");return;}
    uint8_t b[0x100];
    if(!rmem(kl,b,0x100)){printf("   klass unreadable\n");return;}
    for(int o=0;o<0x100;o+=8){
        uint64_t p=spac(*(uint64_t*)(b+o));
        if(!vp(p))continue;
        std::string s=read_cstr(p,80);
        bool printable=!s.empty();
        for(char c:s)if((unsigned char)c<0x20||c>0x7e){printable=false;break;}
        if(printable&&s.size()>2)printf("   klass+0x%03x -> 0x%llx = \"%s\"\n",o,(unsigned long long)p,s.c_str());
    }
}
int main(){
    pid_t pid=find_rust(); if(pid<0){printf("no rust\n");return 1;}
    if(task_for_pid(mach_task_self(),pid,&g_task)!=KERN_SUCCESS){printf("tfp fail\n");return 1;}
    enum_rw();
    // Objects found earlier:
    dump_klass(0x652c88030,"String (klass via +0x10 = name?)");
    dump_klass(0x653d2b000,"X garbage obj");
    dump_klass(0x655731300,"X garbage obj 2");
    dump_klass(0x6566f4fc0,"Construction");
    dump_klass(0x694d9d348,"Transform");
    // also try one of the PlayerCorpse from earlier daemon run
    dump_klass(0x6542ebb08,"PlayerCorpse (from radar_new)");
    return 0;
}
