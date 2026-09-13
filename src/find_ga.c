#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <mach/mach.h>
#include <libproc.h>

int main() {
    // Find Rust pid
    pid_t pids[4096]; int n=proc_listpids(PROC_ALL_PIDS,0,pids,sizeof(pids));
    pid_t pid=-1;
    for(int i=0;i<n/(int)sizeof(pid_t);i++){
        char p[1024];
        if(proc_pidpath(pids[i],p,sizeof(p))>0 && strstr(p,"RustClient")){pid=pids[i];break;}
    }
    if(pid<0){printf("[!] No Rust\n");return 1;}
    printf("PID=%d\n",pid);
    
    task_t task;
    if(task_for_pid(mach_task_self(),pid,&task)!=0){printf("[!] t_f_p\n");return 1;}
    
    vm_address_t a=0;vm_size_t sz;vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt;mach_port_t obj;
    
    while(1){
        cnt=VM_REGION_BASIC_INFO_COUNT_64;
        if(vm_region_64(task,&a,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&cnt,&obj))break;
        char path[256]={0};
        proc_regionfilename(pid,a,path,sizeof(path));
        if(path[0]&&(strstr(path,"GameAssembly")||strstr(path,"RustClient")))
            printf("0x%lx 0x%lx %s %d\n",(unsigned long)a,(unsigned long)sz,path,info.protection);
        a+=sz;
        if(!a)break;
    }
    return 0;
}