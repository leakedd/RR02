// RR02/test_dump2.cpp — Apply dump offsets directly without klass
// Scan objects by checking: obj+0x700 = valid SteamID, obj+0x6F0 = valid PM ptr
// Then read PM+0x2F8 for position, obj+0x2D8 for name

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

// Offsets from Bigpapa1 July 18 dump
static const int BP_userID      = 0x700;
static const int BP_playerModel = 0x6F0;
static const int BP_displayName = 0x2D8;
static const int BP_playerFlags = 0x6B8;
static const int PM_position    = 0x2F8;
static const int PM_newVelocity = 0x31C;

static const uint64_t SID_MIN = 76561197900000000ULL;
static const uint64_t SID_MAX = 76561300000000000ULL;

struct Rg { uint64_t s,e; };

int main() {
    printf("=== RR02 Test Dump Offsets v2 ===\n");
    pid_t pid = find_rust();
    if (pid<0) { printf("[!] Rust not found\n"); return 1; }
    if (task_for_pid(mach_task_self(),pid,&g_task)!=0) { printf("[!] t_f_p\n"); return 1; }

    // Get writable regions
    vm_address_t a=0; vm_size_t sz; vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt; mach_port_t obj;
    static Rg regs[128000]; int rc=0;
    while(rc<128000){
        cnt=VM_REGION_BASIC_INFO_COUNT_64;
        if(vm_region_64(g_task,&a,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&cnt,&obj))break;
        if((info.protection&VM_PROT_READ)&&(info.protection&VM_PROT_WRITE)&&sz<=256*1024*1024) regs[rc++]={(uint64_t)a,(uint64_t)a+sz};
        a+=sz;
    }
    printf("[+] %d writable regions\n", rc);

    static uint8_t buf[8*1024*1024];
    struct Player { uint64_t bp, sid, pm; float x,y,z; std::string name; };
    std::vector<Player> players;

    // Scan for valid SteamID values at random positions,
    // then check if bp-0x700 has PM at -0x700+0x6F0 = -0x10... no that's wrong.
    // 
    // Better: scan for uint64 values in SID range. For each:
    // bp = sid_addr - 0x700 (assume this is the BasePlayer start)
    // Then validate that bp+0x6F0 points to a valid PM
    //
    for(int ri=0;ri<rc&&players.size()<200;ri++){
        if(regs[ri].e-regs[ri].s > 256*1024*1024) continue;
        for(uint64_t off=0;off<regs[ri].e-regs[ri].s;off+=8*1024*1024){
            uint64_t ch=regs[ri].e-regs[ri].s-off; if(ch>8*1024*1024)ch=8*1024*1024;
            vm_size_t got=0;
            if(vm_read_overwrite(g_task,(vm_address_t)(regs[ri].s+off),ch,(vm_address_t)buf,&got))break;
            for(size_t i=0;i+8<=got&&players.size()<200;i+=1){
                uint64_t v; memcpy(&v,buf+i,8);
                if(v<SID_MIN||v>=SID_MAX) continue;
                
                uint64_t bp = regs[ri].s+off+i - BP_userID; // guess BasePlayer start
                if(!vptr(bp)) continue;
                
                // Validate: bp+0x6F0 should be a valid PM ptr
                uint64_t pm = r64(bp + BP_playerModel);
                if(!vptr(pm)) continue;
                
                // Also validate flags
                uint64_t flags = r64(bp + BP_playerFlags);
                if(flags > 0x7FFF) continue; // flags should be reasonable
                
                // Dedup by SID
                bool dup=false;
                for(auto& p:players) if(p.sid==v){dup=true; break;}
                if(dup) continue;
                
                // Read position
                float px=rf(pm+PM_position), py=rf(pm+PM_position+4), pz=rf(pm+PM_position+8);
                bool pos_ok = std::isfinite(px)&&std::isfinite(pz)&&px>-5000&&px<5000&&pz>-5000&&pz<5000;
                
                // Read name
                std::string name = read_str(bp + BP_displayName);
                
                if(pos_ok){
                    Player p;
                    p.bp=bp; p.sid=v; p.pm=pm; p.x=px; p.y=py; p.z=pz; p.name=name;
                    players.push_back(p);
                }
            }
        }
    }

    printf("[+] %zu players with valid positions\n\n", players.size());
    
    // Show all with non-zero positions
    printf("%-12s %-24s %-24s\n", "SID", "Name", "Position");
    for(auto& p:players){
        if(p.x!=0||p.z!=0)
            printf("%-12llu %-24s (%.1f, %.1f, %.1f)\n", p.sid%100000, p.name.c_str(), p.x, p.y, p.z);
    }

    // NOW: test if positions CHANGE by doing 2 snapshots
    if(players.size()>=1){
        printf("\n=== Movement test: 2 snapshots 3s apart ===\n");
        printf("BOUGE TOI EN JEU !\n");
        fflush(stdout);
        
        // Snapshot 1
        struct Snap { uint64_t sid; float x,y,z; };
        std::vector<Snap> s1;
        for(auto& p:players){
            float px=rf(p.pm+PM_position), py=rf(p.pm+PM_position+4), pz=rf(p.pm+PM_position+8);
            if(std::isfinite(px)&&std::isfinite(pz)) s1.push_back({p.sid,px,py,pz});
        }
        
        sleep(3);
        
        // Snapshot 2
        int moved=0;
        for(size_t i=0;i<s1.size();i++){
            float px=rf(players[i].pm+PM_position), py=rf(players[i].pm+PM_position+4), pz=rf(players[i].pm+PM_position+8);
            float dx=px-s1[i].x, dz=pz-s1[i].z;
            float dist=sqrtf(dx*dx+dz*dz);
            if(dist>0.5f){
                moved++;
                printf("  MOVED %llu: (%.1f,%.1f)->(%.1f,%.1f) %.1fm\n", s1[i].sid%100000, s1[i].x,s1[i].z,px,pz,dist);
            }
        }
        printf("  %d/%zu moved\n", moved, s1.size());
    }
    
    return 0;
}
