// RR02/find_base.c - Find GameAssembly by Mach-O magic
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <mach/mach.h>
#include <libproc.h>

int main() {
    pid_t pids[4096];int n=proc_listpids(PROC_ALL_PIDS,0,pids,sizeof(pids));
    pid_t pid=-1;
    for(int i=0;i<n/(int)sizeof(pid_t);i++){char p[1024];if(proc_pidpath(pids[i],p,sizeof(p))>0&&strstr(p,"RustClient")){pid=pids[i];break;}}
    if(pid<0){printf("[!] No Rust\n");return 1;}
    
    task_t task;
    if(task_for_pid(mach_task_self(),pid,&task)!=0){printf("[!] t_f_p\n");return 1;}

    vm_address_t a=0;vm_size_t sz;vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt;mach_port_t obj;

    printf("=== Lookup ===\nPID=%d\n",pid);

    while(1){
        cnt=VM_REGION_BASIC_INFO_COUNT_64;
        if(vm_region_64(task,&a,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&cnt,&obj))break;
        
        // Read first 4 bytes of region
        if(info.protection&1 && sz>=4){
            uint32_t magic=0;
            vm_size_t got=0;
            if(vm_read_overwrite(task,a,4,(vm_address_t)&magic,&got)==0 && got>=4){
                // ARM64 Mach-O magic: 0xFEEDFACF (64-bit LE) or 0xFEEDFACE (32-bit)
                // Universal binary magic: 0xCAFEBABE (BE) or 0xBEBAFECA (LE)
                if(magic==0xFEEDFACF || magic==0xCFACEDFE || magic==0xCAFEBABE){
                    char path[256]={0};
                    proc_regionfilename(pid,a,path,sizeof(path));
                    printf("MACH-O at 0x%lx sz=0x%lx prot=%d path=%s\n",(unsigned long)a,(unsigned long)sz,info.protection,path);
                }
            }
        }
        a+=sz;
        if(!a)break;
    }
    printf("Done.\n");
    return 0;
}