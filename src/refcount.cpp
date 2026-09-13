// refcount — un seul passage mémoire : compte combien de fois chaque valeur cible apparaît (régions RW)
// Usage: refcount <klass_hex> <span_hex>   -> cibles = tous les qwords pointeurs du struct [klass, klass+span)
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <vector>
#include <map>
#include <algorithm>
static task_t T=MACH_PORT_NULL;
static bool rd(uint64_t a,void*b,size_t n){mach_vm_size_t g=0;return mach_vm_read_overwrite(T,a,n,(mach_vm_address_t)b,&g)==KERN_SUCCESS&&g==n;}
int main(int argc,char**argv){
    uint64_t KL=strtoull(argv[1],nullptr,16);
    uint64_t span=argc>2?strtoull(argv[2],nullptr,16):0x400;
    int bytes=proc_listpids(PROC_ALL_PIDS,0,nullptr,0);
    std::vector<pid_t> ps(bytes/4+256);bytes=proc_listpids(PROC_ALL_PIDS,0,ps.data(),ps.size()*4);
    pid_t pid=0;for(int i=0;i<bytes/4;i++){char p[PROC_PIDPATHINFO_MAXSIZE]={};if(proc_pidpath(ps[i],p,sizeof p)>0&&strstr(p,"/RustClient.app/Contents/MacOS/Rust")){pid=ps[i];break;}}
    if(task_for_pid(mach_task_self(),pid,&T)!=KERN_SUCCESS){printf("TFP_FAIL\n");return 1;}
    std::vector<uint8_t> blk(span);rd(KL,blk.data(),span);
    std::map<uint64_t,std::pair<uint64_t,int>> tgt; // valeur -> (offset,count)
    for(uint64_t o=0;o+8<=span;o+=8){
        uint64_t v=*(uint64_t*)(blk.data()+o);
        if(v>0x1000000&&v<0x800000000000ULL)tgt[v]={o,0};
    }
    printf("cibles: %zu\n",tgt.size());
    mach_vm_address_t addr=0;mach_vm_size_t size=0;vm_region_basic_info_data_64_t info;mach_msg_type_number_t ic=VM_REGION_BASIC_INFO_COUNT_64;mach_port_t obj=0;
    const size_t CH=8*1024*1024;std::vector<uint8_t> buf(CH);
    while(1){
        kern_return_t kr=mach_vm_region(T,&addr,&size,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&ic,&obj);
        if(kr!=KERN_SUCCESS)break;
        uint64_t cur=addr,left=size;addr+=size;
        if(!(info.protection&VM_PROT_WRITE))continue;
        while(left>0){size_t n=(left<CH)?(size_t)left:CH;mach_vm_size_t got=0;
            if(mach_vm_read_overwrite(T,cur,n,(mach_vm_address_t)buf.data(),&got)==KERN_SUCCESS)
                for(size_t i=0;i+8<=got;i+=8){
                    uint64_t v=*(uint64_t*)(buf.data()+i);
                    auto it=tgt.find(v);if(it!=tgt.end())it->second.second++;
                }
            if(left<=n)break;cur+=n;left-=n;}
    }
    std::vector<std::pair<int,std::pair<uint64_t,uint64_t>>> rows;
    for(auto&kv:tgt)rows.push_back({kv.second.second,{kv.first,kv.second.first}});
    std::sort(rows.rbegin(),rows.rend());
    for(size_t i=0;i<rows.size()&&i<25;i++)
        printf("  n=%-6d valeur=0x%-12llx (champ klass+0x%llx)\n",rows[i].first,(unsigned long long)rows[i].second.first,(unsigned long long)rows[i].second.second);
    return 0;
}
