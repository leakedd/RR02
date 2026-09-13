// RR02/solve.cpp — Complete solution using Bigpapa1 dump offsets
// 1. Find GameAssembly base via Mach-O magic
// 2. Compute BasePlayer klass = base + 0xFCCA7D0
// 3. Find objects with this klass
// 4. Read player_model at +0x6F0, position at PM+0x2F8
// 5. Build radar data

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

// Find GameAssembly base by scanning for Mach-O magic in executable regions
static uint64_t find_ga_base(pid_t pid) {
    vm_address_t a=0; vm_size_t sz; vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt; mach_port_t obj;
    while(true){
        cnt=VM_REGION_BASIC_INFO_COUNT_64;
        if(vm_region_64(g_task,&a,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&cnt,&obj)) break;
        if(info.protection&VM_PROT_EXECUTE && sz>=4){
            uint32_t magic=0;
            vm_size_t got=0;
            if(vm_read_overwrite(g_task,a,4,(vm_address_t)&magic,&got)==0 && got>=4){
                if(magic==0xFEEDFACF || magic==0xCFACEDFE || magic==0xCAFEBABE){
                    // Found Mach-O - check if it's GameAssembly by looking for IL2CPP strings nearby
                    // GameAssembly contains "il2cpp" or "GameAssembly" strings in its header
                    char buf[256]={0};
                    vm_read_overwrite(g_task,a,256,(vm_address_t)buf,&got);
                    if(strstr(buf,"GameAssembly") || strstr(buf,"il2cpp")){
                        return a;
                    }
                    // Also check if this region is large (GameAssembly is huge)
                    if(sz > 10*1024*1024) { // > 10MB
                        return a;
                    }
                }
            }
        }
        a+=sz;
        if(!a) break;
    }
    return 0;
}

int main() {
    printf("=== RR02 Complete Solution ===\n");
    pid_t pid = find_rust();
    if (pid<0) { printf("[!] Rust not found\n"); return 1; }
    if (task_for_pid(mach_task_self(),pid,&g_task)!=0) { printf("[!] t_f_p\n"); return 1; }

    // Step 1: Find GameAssembly base
    printf("[*] Finding GameAssembly base...\n");
    uint64_t ga_base = find_ga_base(pid);
    printf("[+] GameAssembly base: 0x%llx\n", ga_base);
    if(!ga_base){printf("[!] Can't find GA\n"); return 1;}

    // Step 2: Compute klass from RVA
    uint64_t klass = ga_base + 0xFCCA7D0;
    printf("[+] BasePlayer klass: 0x%llx\n", klass);

    // Verify klass name
    uint64_t name_ptr = r64(klass + 0x10);
    if(vptr(name_ptr)) {
        char nb[64]={0}; read_mem(name_ptr, nb, 32);
        printf("[+] Klass name: %s\n", nb);
    }

    // Step 3: Scan heap for objects with this klass
    printf("[*] Scanning for BasePlayer objects...\n");
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

    printf("[+] %zu players found\n", players.size());
    
    // Show all with positions
    int nz=0;
    for(auto& p:players){
        if(p.x!=0||p.z!=0){
            printf("  SID=%llu name=%s pos=(%.1f,%.1f,%.1f)\n", 
                   p.sid%100000, p.name.c_str(), p.x, p.y, p.z);
            nz++;
        }
    }
    printf("[+] %d with non-zero positions\n", nz);

    // Step 4: Movement test
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

    // Step 5: Write JSON for radar
    FILE* f=fopen("/Users/mac/Desktop/RR02/radar_data.json","w");
    if(f){
        fprintf(f,"{\n  \"local\": {\"x\": %.2f, \"y\": %.2f, \"z\": %.2f, \"name\": \"local\"},\n  \"players\": [\n",
                players.empty()?0:players[0].x, players.empty()?0:players[0].y, players.empty()?0:players[0].z);
        bool first=true;
        for(auto& p:players){
            if(!first)fprintf(f,",\n");
            first=false;
            fprintf(f,"    {\"name\":\"%s\",\"x\":%.2f,\"y\":%.2f,\"z\":%.2f,\"dist\":0,\"sid\":%llu}",
                    p.name.c_str(),p.x,p.y,p.z,p.sid);
        }
        fprintf(f,"\n  ]\n}\n");
        fclose(f);
        printf("[+] JSON written to /Users/mac/Desktop/RR02/radar_data.json\n");
    }

    return 0;
}