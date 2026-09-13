// probe_klass2.cpp — raw dump of klass header + locate fields via name-string scan
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <mach/mach.h>

static mach_port_t task;
static uint64_t r64(uint64_t a) { uint64_t v=0; mach_msg_type_number_t s=0; vm_read(task,(vm_address_t)a,8,(vm_offset_t*)&v,&s); return v; }

static bool read_str(uint64_t a, char* out, int max) {
    mach_msg_type_number_t sz = 0; char buf[4096]={0};
    if (vm_read(task,(vm_address_t)a,(mach_msg_type_number_t)(max<4095?max:4095),(vm_offset_t*)buf,&sz)!=KERN_SUCCESS) return false;
    for (int i=0;i<(int)sz;i++){ if(buf[i]<0x20||buf[i]>0x7e){buf[i]=0;break;} }
    strncpy(out,buf,max); return out[0]!=0;
}

int main(){
    if (task_for_pid(mach_task_self(),2541,&task)!=KERN_SUCCESS){printf("tfp failed\n");return 1;}
    uint64_t vtable=0x10399bac0;
    uint64_t klass=r64(vtable);
    printf("vtable[0]=0x%llx\n",(unsigned long long)klass);
    // dump first 0x100 bytes as qwords
    for (int i=0;i<0x100;i+=8){
        uint64_t v=r64(klass+i);
        // check if v points to printable string
        char s[256]={0};
        bool isstr = v>0x100000000ULL && v<0x200000000ULL && read_str(v,s,200);
        if (isstr) printf("+0x%03x: 0x%llx  -> '%s'\n",i,(unsigned long long)v,s);
        else printf("+0x%03x: 0x%llx\n",i,(unsigned long long)v);
    }
    return 0;
}
