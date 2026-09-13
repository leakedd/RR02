// RR02/pointers.cpp — Follow potential entity pointers from the list
// Look for entries with small values (potential pointers) and follow them

#include <cstdio>
#include <cstdint>
#include <cmath>
#include <vector>
#include <algorithm>
#include <unistd.h>
#include <mach/mach.h>
#include <libproc.h>

static task_t g_task;
static bool rm(uint64_t a,void*b,size_t s){vm_size_t g=0;return vm_read_overwrite(g_task,(vm_address_t)a,s,(vm_address_t)b,&g)==0&&g==s;}
static uint64_t r64(uint64_t a){uint64_t v=0;rm(a,&v,8);return v;}
static float rf(uint64_t a){float v=0;rm(a,&v,4);return v;}
static bool vptr(uint64_t p){return p>0x100000ULL&&p<0x800000000000ULL;}
static bool is_sid(uint64_t v){return v>=76561197900000000ULL&&v<76561300000000000ULL;}
static bool is_world(float x,float y,float z){return std::isfinite(x)&&std::isfinite(z)&&x>-4100&&x<4100&&z>-4100&&z<4100&&y>-500&&y<3000;}
static pid_t fr(){pid_t pids[4096];int n=proc_listpids(PROC_ALL_PIDS,0,pids,sizeof(pids));for(int i=0;i<n/(int)sizeof(pid_t);i++){char p[1024];if(proc_pidpath(pids[i],p,sizeof(p))>0&&strstr(p,"RustClient"))return pids[i];}return -1;}

int main(){
    printf("=== Pointer Analysis ===\n");
    pid_t pid=fr();if(pid<0){printf("[!] No Rust\n");return 1;}
    if(task_for_pid(mach_task_self(),pid,&g_task)!=0){printf("[!] t_f_p\n");return 1;}

    // Read the list entries starting from 0x119f10668
    uint64_t list_start=0x119f10668;
    printf("[*] Reading list from 0x%llx\n",list_start);
    
    // Read 100 entries (0x10 bytes each = 0x640 bytes)
    uint8_t data[0x800];
    if(!rm(list_start,data,0x800)){printf("[!] Can't read list\n");return 1;}
    
    // Parse entries
    struct Entry{uint64_t ptr;uint64_t sid;};
    std::vector<Entry> entries;
    for(int i=0;i<0x800-16;i+=0x10){
        uint64_t p=*(uint64_t*)(data+i);
        uint64_t s=*(uint64_t*)(data+i+8);
        if(is_sid(s)){
            entries.push_back({p,s});
        }
    }
    printf("[+] %zu entries with SteamID\n",entries.size());
    
    // Show all entries with their pointer values
    printf("\n=== Entries ===\n");
    printf("%-8s %-18s %-16s %-10s\n","#","Pointer","SID","Valid?");
    for(size_t i=0;i<entries.size();i++){
        auto& e=entries[i];
        bool ptr_ok=vptr(e.ptr);
        printf("%-8zu 0x%-16llx %-16llu %s\n",i,e.ptr,e.sid%100000,ptr_ok?"YES":"NO");
        
        // If pointer looks valid, follow it
        if(ptr_ok){
            // Read first 0x800 bytes at that pointer
            uint8_t ent[0x800];
            if(rm(e.ptr,ent,0x800)){
                // Check if this looks like an entity (has vtable)
                uint64_t vtable=*(uint64_t*)ent;
                bool is_entity=vptr(vtable)&&vtable>0x100000000ULL;
                printf("  -> 0x%llx: vtable=0x%llx %s\n",e.ptr,vtable,is_entity?"ENTITY":"");
                
                // Look for position in this structure
                for(int po=0x100;po<0x800;po+=4){
                    float px,pz;
                    memcpy(&px,ent+po,4);memcpy(&pz,ent+po+8,4);
                    if(std::isfinite(px)&&std::isfinite(pz)&&px>-5000&&px<5000&&pz>-5000&&pz<5000&&(px!=0||pz!=0)){
                        printf("    POSSIBLE POS at +0x%x: (%.1f,%.1f)\n",po,px,pz);
                    }
                }
            }
        }
    }
    
    return 0;
}