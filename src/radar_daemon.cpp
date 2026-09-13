// ============================================================================
// RR02 radar_daemon v17 - FINAL clean approach (immobile-safe local lock)
// Build 24614784, macOS ARM64. External only (task_for_pid, NO injection).
//
// PROVEN FACTS (session 2026-08-12):
//   - SteamID scan -> 0 false positives (props/spawns have no valid SID)
//   - Distant player LIVE position: obj+0x260 -> ptr -> +0x1a0 (Vector3)
//     This chain gives 0/garbage for SIDs not currently RENDERED client-side
//     (out of draw distance / culled) -> that's a FEATURE: it naturally
//     filters to only nearby, currently-visible players. No noise.
//   - Local position: found via mover-scan seeded on last known good pos,
//     then LOCKED to that single address and re-read every tick.
//     IMPROVEMENT v17: if no mover is detected (player immobile), fall back
//     to the closest valid-world float3 to the seed (no movement required).
// ============================================================================
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <cstdlib>
#include <unistd.h>
#include <vector>
#include <map>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>

#define SID_MIN 76561198000000000ULL
#define SID_MAX 76561200000000000ULL

// seed anchor: last known-good local pos (update if you respawn far away)
static float SEED_X = -341.24f, SEED_Y = 7.59f, SEED_Z = 1593.58f;

static task_t g_task;
static int    g_pid=-1;

static bool r64(uint64_t a, uint64_t& o){
    if(a<0x1000||a>0x7FFFFFFFFFFFULL)return false;
    mach_vm_size_t s; return mach_vm_read_overwrite(g_task,a,8,(vm_address_t)&o,&s)==KERN_SUCCESS;
}
static uint64_t r64d(uint64_t a){ uint64_t o=0; r64(a,o); return o; }
static float rf(uint64_t a){ float f=0; if(a<0x1000||a>0x7FFFFFFFFFFFULL)return 0;
    mach_vm_size_t s; mach_vm_read_overwrite(g_task,a,4,(vm_address_t)&f,&s); return f; }

static bool valid_world(float x,float y,float z){
    return std::isfinite(x)&&std::isfinite(y)&&std::isfinite(z)
        &&std::fabs(x)>5.f&&std::fabs(z)>5.f
        &&std::fabs(x)<6000.f&&std::fabs(z)<6000.f
        &&y>-250.f&&y<1500.f;
}

// ---- SID scan: find all player object base addresses (0 noise) ----
struct Player{ uint64_t base; uint64_t sid; };
static std::vector<Player> scan_players(){
    std::vector<Player> out;
    std::vector<uint8_t> buf(16*1024*1024);
    mach_vm_address_t a=0; mach_vm_size_t sz;
    vm_region_basic_info_data_64_t info; mach_msg_type_number_t cnt=VM_REGION_BASIC_INFO_COUNT_64; mach_port_t obj;
    std::map<uint64_t,uint64_t> by_sid;
    while(mach_vm_region(g_task,&a,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&cnt,&obj)==KERN_SUCCESS){
        if(!(info.protection&VM_PROT_READ)){a+=sz;continue;}
        if(a>0x200000000ULL)break;
        uint64_t rs=sz; if(rs>512ULL*1024*1024||rs<0x4000){a+=sz;continue;}
        for(uint64_t o=0;o<rs;o+=buf.size()){
            uint64_t tr=std::min((uint64_t)buf.size(),rs-o);
            mach_vm_size_t got=0;
            if(tr<8)continue;
            if(mach_vm_read_overwrite(g_task,a+o,tr,(vm_address_t)buf.data(),&got)!=KERN_SUCCESS)continue;
            for(size_t i=0;i+8<=(size_t)got;i+=8){
                uint64_t v; memcpy(&v,buf.data()+i,8);
                if(v<SID_MIN||v>=SID_MAX)continue;
                if(by_sid.count(v))continue; // already have a validated base for this SID
                uint64_t sid_addr=a+o+i;
                uint64_t best_base=0;
                // Accept a candidate only if its vtable is valid (real managed object,
                // not a config/network copy of the SID which has +0 == 0/garbage).
                // We do NOT require the +0x260 chain to be valid here: rendered-vs-culled
                // players legitimately have +0x260 == 0. Chain validity is checked live.
                for(uint64_t k=0x400;k<=0x800;k+=8){
                    uint64_t cand=sid_addr-k;
                    if(r64d(cand+k)!=v) continue;
                    uint64_t vt=r64d(cand+0);
                    if(vt<0x1000||vt>0x7FFFFFFFFFFFULL) continue;
                    uint64_t klass=r64d(vt+0);
                    if(klass<0x1000||klass>0x7FFFFFFFFFFFULL) continue;
                    best_base=cand; break;
                }
                if(best_base) by_sid[v]=best_base;
                // else: no valid managed-object base at this occurrence; keep scanning
            }
        }
        a+=sz;
    }
    for(auto& kv : by_sid) out.push_back({kv.second, kv.first});
    return out;
}

// ---- Distant player live position via the proven +0x260 -> +0x1a0 chain ----
// Returns false if this player is not currently rendered (chain is 0/invalid) --
// that's expected and correct: only render-active nearby players pass.
static bool read_distant(uint64_t base, float& x,float& y,float& z){
    uint64_t p = r64d(base+0x260);
    if(p<0x1000||p>0x7FFFFFFFFFFFULL) return false;
    x=rf(p+0x1a0); y=rf(p+0x1a4); z=rf(p+0x1a8);
    return valid_world(x,y,z);
}

// ---- Local: one-time mover-scan locked to a single address, then just re-read ----
// v17: if no mover moves (player immobile), fall back to closest valid-world
// float3 to the seed (no movement required) so local is always found.
static uint64_t g_local_addr=0;

static uint64_t find_local_mover(){
    std::map<uint64_t,std::vector<float>> A;
    mach_vm_address_t a=0; mach_vm_size_t sz;
    vm_region_basic_info_data_64_t info; mach_msg_type_number_t cnt=VM_REGION_BASIC_INFO_COUNT_64; mach_port_t obj;
    while(mach_vm_region(g_task,&a,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&cnt,&obj)==KERN_SUCCESS){
        if(!(info.protection&VM_PROT_READ)){a+=sz;continue;}
        if(a>0x200000000ULL)break;
        uint64_t rs=sz; if(rs>256ULL*1024*1024||rs<0x2000){a+=sz;continue;}
        std::vector<uint8_t> buf(rs);
        if(mach_vm_read_overwrite(g_task,a,rs,(vm_address_t)buf.data(),&rs)!=KERN_SUCCESS){a+=sz;continue;}
        for(uint64_t o=0;o+0xc<=rs;o+=4){
            float x,y,z; memcpy(&x,buf.data()+o,4);memcpy(&y,buf.data()+o+4,4);memcpy(&z,buf.data()+o+8,4);
            float dx=x-SEED_X,dy=y-SEED_Y,dz=z-SEED_Z;
            if(valid_world(x,y,z) && (dx*dx+dy*dy+dz*dz)<(400.f*400.f)) A[a+o]={x,y,z};
        }
        a+=sz;
    }
    usleep(1500000);
    uint64_t best=0; float bestd=1e18f;
    uint64_t best_static=0; float bestd_static=1e18f;
    for(auto& kv : A){
        float x=rf(kv.first),y=rf(kv.first+4),z=rf(kv.first+8);
        if(!valid_world(x,y,z))continue;
        float ddx=x-SEED_X,ddy=y-SEED_Y,ddz=z-SEED_Z;
        float d=ddx*ddx+ddy*ddy+ddz*ddz;
        float dx=x-kv.second[0],dy=y-kv.second[1],dz=z-kv.second[2];
        float moved=sqrtf(dx*dx+dy*dy+dz*dz);
        if(moved>=1.f){ if(d<bestd){bestd=d;best=kv.first;} }
        else { if(d<bestd_static){bestd_static=d;best_static=kv.first;} }
    }
    // Prefer a mover only if it is reasonably close to the seed (player moved <400m).
    // Otherwise fall back to the closest static candidate (immobile local).
    if(best && bestd < (400.f*400.f)) return best;
    return best_static;
}

static void write_json(const std::string& j){
    FILE* f=fopen("/tmp/rr02_radar.json","w");
    if(f){ fputs(j.c_str(),f); fclose(f); }
}

int main(){
    setvbuf(stdout,0,0,_IONBF);
    pid_t pids[8192]; int n=proc_listpids(PROC_ALL_PIDS,0,pids,sizeof(pids));
    for(int i=0;i<n/(int)sizeof(pid_t);i++){ if(!pids[i])continue;
        char pa[PROC_PIDPATHINFO_MAXSIZE]={}; if(proc_pidpath(pids[i],pa,sizeof(pa))>0&&strstr(pa,"RustClient")){g_pid=pids[i];break;}
    }
    if(g_pid<0){printf("[!] RustClient not found\n");return 1;}
    if(task_for_pid(mach_task_self(),g_pid,&g_task)!=KERN_SUCCESS){printf("[!] task_for_pid\n");return 1;}
    printf("[+] RustClient pid=%d\n",g_pid);

    std::vector<Player> players = scan_players();
    printf("[*] SID scan: %zu players found\n", players.size());

    g_local_addr = find_local_mover();
    if(g_local_addr) printf("[+] local locked at 0x%llx\n",(unsigned long long)g_local_addr);
    else printf("[!] local not found (adjust SEED_X/Y/Z to your current position and restart)\n");

    int tick=0;
    while(true){
        tick++;
        if(tick%100==0){
            players = scan_players(); // refresh player list every ~10s (cheap, no mover-scan)
        }

        float lx=0,ly=0,lz=0;
        if(g_local_addr){ lx=rf(g_local_addr);ly=rf(g_local_addr+4);lz=rf(g_local_addr+8); }
        if(!valid_world(lx,ly,lz)){
            // local address died (respawn/teleport) -> re-lock using last good pos as new seed
            if(lx||ly||lz){ SEED_X=lx; SEED_Y=ly; SEED_Z=lz; }
            g_local_addr = find_local_mover();
            if(g_local_addr){ lx=rf(g_local_addr);ly=rf(g_local_addr+4);lz=rf(g_local_addr+8); }
        }

        std::string json="{\"local\":{\"x\":"+std::to_string(lx)+",\"y\":"+std::to_string(ly)+",\"z\":"+std::to_string(lz)+"},\"players\":[";
        bool first=true; int id=1;
        for(auto& p : players){
            float x,y,z;
            if(!read_distant(p.base,x,y,z)) continue; // not rendered right now -> skip, correct behavior
            float d=std::sqrt((x-lx)*(x-lx)+(z-lz)*(z-lz));
            if(!first) json+=",";
            first=false;
            json+="{\"id\":"+std::to_string(id++)+",\"x\":"+std::to_string(x)+",\"y\":"+std::to_string(y)+",\"z\":"+std::to_string(z)+",\"dist\":"+std::to_string(d)+",\"sid\":"+std::to_string(p.sid)+"}";
        }
        json+="]}";
        write_json(json);

        if(tick%50==0){
            int visible=0; for(auto& p:players){float x,y,z; if(read_distant(p.base,x,y,z))visible++;}
            printf(" tick=%d local=(%.1f,%.1f,%.1f) known_sids=%zu visible_now=%d\n",tick,lx,ly,lz,players.size(),visible);
        }
        usleep(100000);
    }
    return 0;
}
