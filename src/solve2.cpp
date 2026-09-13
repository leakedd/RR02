// RR02/solve2.cpp — Robust solution: find klass by name, then objects, then dump offsets
// 1. Scan heap for Il2CppClass with name "BasePlayer"
// 2. Find all objects pointing to this klass
// 3. Use dump offsets: userID=0x700, player_model=0x6F0, position=0x2F8, name=0x2D8

#include <cstdio>
#include <cstdint>
#include <cmath>
#include <cstring>
#include <vector>
#include <string>
#include <algorithm>
#include <unistd.h>
#include <mach/mach.h>
#include <libproc.h>

static task_t g_task;
static bool read_mem(uint64_t addr, void* buf, size_t size) {
    vm_size_t got = 0;
    return vm_read_overwrite(g_task, (vm_address_t)addr, size, (vm_address_t)buf, &got) == KERN_SUCCESS && got == size;
}
static uint64_t r64(uint64_t a) { uint64_t v=0; read_mem(a,&v,8); return v; }
static float rf(uint64_t a) { float v=0; read_mem(a,&v,4); return v; }
static bool vptr(uint64_t p) { return p>0x100000ULL&&p<0x800000000000ULL; }

static std::string read_str(uint64_t addr) {
    uint64_t str = r64(addr);
    if (!vptr(str)) return "";
    uint32_t len; read_mem(str+0x10,&len,4);
    if (len==0||len>64) return "";
    std::string out;
    for (uint32_t i=0;i<len&&i<63;i++) {
        uint16_t c; read_mem(str+0x14+i*2,&c,2);
        if (c==0) break;
        if (c>31&&c<127) out+=(char)c; else out+='?';
    }
    return out;
}

static pid_t find_rust() {
    pid_t pids[4096]; int n=proc_listpids(PROC_ALL_PIDS,0,pids,sizeof(pids));
    for (int i=0;i<n/(int)sizeof(pid_t);i++) {
        char p[1024]; if(proc_pidpath(pids[i],p,sizeof(p))>0&&strstr(p,"RustClient")) return pids[i];
    }
    return -1;
}

// Find Il2CppClass by name in heap
static uint64_t find_klass_by_name(const char* target) {
    struct Rg { uint64_t s,e; };
    static Rg regs[128000]; int rc=0;
    vm_address_t a=0; vm_size_t sz; vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt; mach_port_t obj;
    while(rc<128000){
        cnt=VM_REGION_BASIC_INFO_COUNT_64;
        if(vm_region_64(g_task,&a,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&cnt,&obj))break;
        if((info.protection&VM_PROT_READ)&&sz<=64*1024*1024) regs[rc++]={(uint64_t)a,(uint64_t)a+sz};
        a+=sz;
    }

    static uint8_t buf[8*1024*1024];
    std::vector<uint64_t> candidates;

    // Scan for Il2CppClass: name at +0x10 points to target string
    for(int ri=0;ri<rc&&candidates.size()<1000;ri++){
        for(uint64_t off=0;off<regs[ri].e-regs[ri].s;off+=8*1024*1024){
            uint64_t ch=regs[ri].e-regs[ri].s-off; if(ch>8*1024*1024)ch=8*1024*1024;
            vm_size_t got=0;
            if(vm_read_overwrite(g_task,(vm_address_t)(regs[ri].s+off),ch,(vm_address_t)buf,&got))break;
            for(size_t i=0;i+8<=got;i+=8){
                uint64_t klass=regs[ri].s+off+i;
                uint64_t name_ptr=0; memcpy(&name_ptr,buf+i,8);
                if(!vptr(name_ptr)) continue;
                // Read string at name_ptr
                char name[32]={0};
                if(!read_mem(name_ptr,name,31)) continue;
                name[31]=0;
                if(strcmp(name,target)==0){
                    candidates.push_back(klass);
                    if(candidates.size()>=1000) break;
                }
            }
        }
    }

    if(candidates.empty()) return 0;
    return candidates[0]; // Return first match
}

int main() {
    printf("=== RR02 Solution v2 ===\n");
    pid_t pid = find_rust();
    if (pid<0) { printf("[!] Rust not found\n"); return 1; }
    if (task_for_pid(mach_task_self(),pid,&g_task)!=0) { printf("[!] t_f_p\n"); return 1; }

    // Find BasePlayer klass by name
    printf("[*] Finding BasePlayer klass...\n");
    uint64_t klass = find_klass_by_name("BasePlayer");
    printf("[+] BasePlayer klass: 0x%llx\n", klass);
    if(!klass){printf("[!] Klass not found\n"); return 1;}

    // Scan heap for objects with this klass at offset 0
    printf("[*] Scanning for objects...\n");
    struct Rg { uint64_t s,e; };
    static Rg regs[128000]; int rc=0;
    vm_address_t a=0; vm_size_t sz; vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt; mach_port_t obj;
    while(rc<128000){
        cnt=VM_REGION_BASIC_INFO_COUNT_64;
        if(vm_region_64(g_task,&a,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&cnt,&obj))break;
        if((info.protection&VM_PROT_READ)&&(info.protection&VM_PROT_WRITE)&&sz<=64*1024*1024) regs[rc++]={(uint64_t)a,(uint64_t)a+sz};
        a+=sz;
    }

    static uint8_t buf[8*1024*1024];
    struct Player { uint64_t bp, sid, pm; float x,y,z; std::string name; };
    std::vector<Player> players;

    for(int ri=0;ri<rc&&players.size()<200;ri++){
        for(uint64_t off=0;off<regs[ri].e-regs[ri].s;off+=8*1024*1024){
            uint64_t ch=regs[ri].e-regs[ri].s-off; if(ch>8*1024*1024)ch=8*1024*1024;
            vm_size_t got=0;
            if(vm_read_overwrite(g_task,(vm_address_t)(regs[ri].s+off),ch,(vm_address_t)buf,&got))break;
            for(size_t i=0;i+8<=got;i+=8){
                uint64_t v; memcpy(&v,buf+i,8);
                if(v!=klass) continue;
                uint64_t bp=regs[ri].s+off+i;
                
                uint64_t sid=r64(bp+0x700);
                if(sid<76561197900000000ULL||sid>=76561300000000000ULL) continue;
                
                uint64_t pm=r64(bp+0x6F0);
                if(!vptr(pm)) continue;
                
                float px=rf(pm+0x2F8), py=rf(pm+0x2F8+4), pz=rf(pm+0x2F8+8);
                if(!std::isfinite(px)||!std::isfinite(pz)) continue;
                if(px<-5000||px>5000||pz<-5000||pz>5000) continue;
                
                // Dedup
                bool dup=false;
                for(auto& p:players) if(p.sid==sid){dup=true;break;}
                if(dup) continue;
                
                std::string name = read_str(bp+0x2D8);
                
                Player p;
                p.bp=bp; p.sid=sid; p.pm=pm; p.x=px; p.y=py; p.z=pz; p.name=name;
                players.push_back(p);
            }
        }
    }

    printf("[+] %zu players\n", players.size());
    
    // Show all
    int nz=0;
    for(auto& p:players){
        if(p.x!=0||p.z!=0){
            printf("  SID=%llu name=%s pos=(%.1f,%.1f,%.1f)\n", 
                   p.sid%100000, p.name.c_str(), p.x, p.y, p.z);
            nz++;
        }
    }
    printf("[+] %d non-zero\n", nz);

    // Movement test
    if(!players.empty()){
        printf("\n=== Movement test (2s) ===\n");
        struct Snap{uint64_t pm; float x,z;};
        std::vector<Snap> s1;
        for(auto& p:players){
            s1.push_back({p.pm, rf(p.pm+0x2F8), rf(p.pm+0x2F8+8)});
        }
        sleep(2);
        int moved=0;
        for(size_t i=0;i<players.size();i++){
            float nx=rf(players[i].pm+0x2F8), nz=rf(players[i].pm+0x2F8+8);
            float dx=nx-s1[i].x, dz=nz-s1[i].z, dist=sqrtf(dx*dx+dz*dz);
            if(dist>0.5f){
                printf("  MOVED SID=%llu: (%.1f,%.1f)->(%.1f,%.1f) %.1fm\n",
                       players[i].sid%100000, s1[i].x,s1[i].z,nx,nz,dist);
                moved++;
            }
        }
        printf("  %d/%zu moved\n", moved, players.size());
    }

    // Write JSON
    FILE* f=fopen("/Users/mac/Desktop/RR02/radar_data.json","w");
    if(f){
        float lx=players.empty()?0:players[0].x;
        float ly=players.empty()?0:players[0].y;
        float lz=players.empty()?0:players[0].z;
        fprintf(f,"{\n  \"local\": {\"x\": %.2f, \"y\": %.2f, \"z\": %.2f, \"name\": \"local\"},\n  \"players\": [\n",lx,ly,lz);
        bool first=true;
        for(auto& p:players){
            if(!first)fprintf(f,",\n");
            first=false;
            fprintf(f,"    {\"name\":\"%s\",\"x\":%.2f,\"y\":%.2f,\"z\":%.2f,\"dist\":0,\"sid\":%llu}",
                    p.name.c_str(),p.x,p.y,p.z,p.sid);
        }
        fprintf(f,"\n  ]\n}\n");
        fclose(f);
        printf("[+] JSON written\n");
    }

    return 0;
}