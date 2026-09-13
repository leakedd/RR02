// RR02/quick.c - dump 3 entity list entries
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <mach/mach.h>
#include <libproc.h>
int main(){
    pid_t pids[4096];int n=proc_listpids(PROC_ALL_PIDS,0,pids,sizeof(pids));pid_t pid=-1;
    for(int i=0;i<n/(int)sizeof(pid_t);i++){char p[1024];if(proc_pidpath(pids[i],p,sizeof(p))>0&&strstr(p,"RustClient")){pid=pids[i];break;}}
    task_t t;if(task_for_pid(mach_task_self(),pid,&t)){printf("[!] t_f_p\n");return 1;}
    uint64_t addrs[]={0xa42d7f1e0,0xa42d7f1f8,0xa42d7f210,0xa42d7f228,0xa42d7f240,0xa42d7f258,0xa42d7f270,0xa42d7f288,0xa42d7f2a0};
    for(int i=0;i<9;i++){
        uint64_t a=addrs[i];
        uint64_t d[5]; // read 5*8=40 bytes per entry
        vm_size_t got=0;
        vm_read_overwrite(t,(vm_address_t)a,40,(vm_address_t)d,&got);
        printf("0x%llx: %016llx %016llx %016llx %016llx %016llx  SID(+0x388)=",a,d[0],d[1],d[2],d[3],d[4]);
        // Read SID from +0x388
        uint64_t sid=0;
        vm_read_overwrite(t,(vm_address_t)(a+0x388),8,(vm_address_t)&sid,&got);
        printf("%llu\n",sid%100000);
        // If d[0] is a pointer, read what it points to
        if(d[0]>0x10000&&d[0]<0x800000000000){
            uint64_t target[5]={0};
            vm_read_overwrite(t,(vm_address_t)d[0],40,(vm_address_t)target,&got);
            printf("  -> d[0] points to 0x%llx: %016llx %016llx %016llx %016llx %016llx\n",d[0],target[0],target[1],target[2],target[3],target[4]);
        }
    }
    return 0;
}