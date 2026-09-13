// qcheck.cpp — quick check: old hardcoded local pos + find PlayerModel offset in new container
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#include <unistd.h>

static task_t g_task;
static float rf(uint64_t a) { float v=0; vm_size_t g=0; vm_read_overwrite(g_task,(vm_address_t)a,4,(vm_address_t)&v,&g); return v; }
static uint64_t r64(uint64_t a) { uint64_t v=0; vm_size_t g=0; vm_read_overwrite(g_task,(vm_address_t)a,8,(vm_address_t)&v,&g); return v; }
static bool rmem(uint64_t a, void* b, size_t s) { vm_size_t g=0; return vm_read_overwrite(g_task,(vm_address_t)a,s,(vm_address_t)b,&g)==KERN_SUCCESS&&(size_t)g==s; }
static bool vptr(uint64_t p) { return p>0x10000ULL&&p<0x7FFFFFFFFFFFULL; }
static const char* cstr(uint64_t a) { static char b[64]; vm_size_t g=0; vm_read_overwrite(g_task,(vm_address_t)a,63,(vm_address_t)b,&g); b[g<63?g:63]=0; return b; }

static pid_t find_rust() {
    pid_t pids[8192]; int n=proc_listpids(PROC_ALL_PIDS,0,pids,sizeof(pids));
    for(int i=0;i<n/(int)sizeof(pid_t);i++){
        if(!pids[i])continue;char pa[PROC_PIDPATHINFO_MAXSIZE]={};
        if(proc_pidpath(pids[i],pa,sizeof(pa))>0&&strstr(pa,"RustClient"))return pids[i];
    }
    return -1;
}

int main() {
    pid_t pid=find_rust();
    if(pid<0){printf("[!]Rust not found\n");return 1;}
    if(task_for_pid(mach_task_self(),pid,&g_task)!=KERN_SUCCESS){printf("[!]tfp\n");return 1;}

    // Old hardcoded local
    uint64_t old=0x68aaec980ULL;
    printf("=== Old hardcoded local (0x68aaec980) ===\n");
    printf("  vtable = 0x%llx\n",(unsigned long long)r64(old));
    printf("  pos @+0x1168 = (%.2f,%.2f,%.2f)\n",rf(old+0x1168),rf(old+0x1168+4),rf(old+0x1168+8));
    printf("  sid @+0x1b0 = %llu\n",(unsigned long long)r64(old+0x1b0));
    printf("  klass name: %s\n",cstr(r64(old)+0x10));

    // New local container from rescan
    uint64_t loc=0x684b9a8d0ULL;
    printf("\n=== New local container (0x684b9a8d0) ===\n");
    uint64_t vt=r64(loc);
    printf("  vtable = 0x%llx\n",(unsigned long long)vt);
    printf("  klass name: %s\n",cstr(vt+0x10));
    printf("  sid @+0x1b0 = %llu\n",(unsigned long long)r64(loc+0x1b0));
    printf("  pos @+0x1168 = (%.2f,%.2f,%.2f)\n",rf(loc+0x1168),rf(loc+0x1168+4),rf(loc+0x1168+8));

    // Test ALL PlayerModel offsets on this container
    printf("\n=== Testing PlayerModel offsets ===\n");
    int pm_offsets[]={0x340,0x508,0x6F0,0x4a8,0x3a0,0x398,0x348,0x500,0x700,0x2e8,0x320,0x360,0x380,0x3c0,0x400,0x450,0x480,0x4c0,0x550,0x600,0x680,0x750,0x800};
    for(int o:pm_offsets){
        uint64_t pm=r64(loc+o);
        if(!vptr(pm))continue;
        float px=rf(pm+0x2F8),py=rf(pm+0x2F8+4),pz=rf(pm+0x2F8+8);
        if(std::isfinite(px)&&std::isfinite(py)&&std::isfinite(pz)&&py>0.5f&&py<2000.f){
            printf("  +0x%03x: pm=0x%llx pos@+0x2F8=(%.1f,%.1f,%.1f) pm_klass=%s\n",
                o,(unsigned long long)pm,px,py,pz,cstr(r64(pm)+0x10));
        }
    }

    // Also scan for the known local position (-147.31,30.99,1517.65) in container
    printf("\n=== Searching for local pos (-147.31,30.99,1517.65) in container ±0x4000 ===\n");
    uint8_t buf[0x4000];
    if(rmem(loc,buf,sizeof(buf))){
        for(int i=0;i+12<=(int)sizeof(buf);i+=4){
            float fx,fy,fz;
            memcpy(&fx,buf+i,4);memcpy(&fy,buf+i+4,4);memcpy(&fz,buf+i+8,4);
            if(fabsf(fx+147.31f)<0.1f&&fabsf(fy-30.99f)<0.1f&&fabsf(fz-1517.65f)<0.1f){
                printf("  FOUND at +0x%x: (%.2f,%.2f,%.2f)\n",i,fx,fy,fz);
            }
        }
    }
    return 0;
}
