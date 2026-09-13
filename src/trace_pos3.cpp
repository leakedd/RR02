// =============================================================================
// trace_pos3.cpp — Find REAL BasePlayer via m_CachedPtr filter
//
// Key insight: Real managed IL2CPP objects (BasePlayer inheriting from
// UnityEngine.Object) have a valid m_CachedPtr pointer at +0x10.
// Items/deployables stored as plain data DON'T.
//
// This eliminates ALL false positives from ownerID fields on items.
//
// Compile: c++ -O2 -std=c++17 -o trace_pos3 trace_pos3.cpp
// Run:     sudo ./trace_pos3
// =============================================================================

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <vector>
#include <map>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <algorithm>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>

static task_t g_task;
static bool rmem(uint64_t a, void* b, size_t s) {
    vm_size_t got = 0;
    return vm_read_overwrite(g_task, (vm_address_t)a, s, (vm_address_t)b, &got) == KERN_SUCCESS && (size_t)got == s;
}
static uint64_t r64(uint64_t a) { uint64_t v=0; rmem(a,&v,8); return v; }
static float rf(uint64_t a) { float v=0; rmem(a,&v,4); return v; }
static uint64_t spac(uint64_t p) { return p & 0x0000FFFFFFFFFFFFULL; }
static bool vp(uint64_t p) { uint64_t s=spac(p); return s>0x10000ULL && s<0x7FFFFFFFFFFFULL; }

static pid_t find_rust() {
    pid_t pids[8192]; int n=proc_listpids(PROC_ALL_PIDS,0,pids,sizeof(pids));
    for(int i=0;i<n/(int)sizeof(pid_t);i++){
        if(!pids[i])continue; char path[PROC_PIDPATHINFO_MAXSIZE]={};
        if(proc_pidpath(pids[i],path,sizeof(path))>0 && strstr(path,"Rust")) return pids[i];
    } return -1;
}

struct Rg{uint64_t s,e;};
static std::vector<Rg> g_rw;
static void enum_rg(){
    mach_vm_address_t a=0;mach_vm_size_t sz;vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt;mach_port_t obj;
    while(true){cnt=VM_REGION_BASIC_INFO_COUNT_64;
        if(mach_vm_region(g_task,&a,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&cnt,&obj)!=KERN_SUCCESS)break;
        if((info.protection&VM_PROT_READ)&&(info.protection&VM_PROT_WRITE))g_rw.push_back({a,a+sz});
        a+=sz;}
}

static const uint64_t SMIN=76561198000000000ULL, SMAX=76561200000000000ULL;
struct SH{uint64_t addr,sid;};

static std::vector<SH> scan_sids(){
    std::vector<SH> h; const size_t C=4*1024*1024; std::vector<uint8_t> buf(C);
    for(auto&r:g_rw){uint64_t rs=r.e-r.s;if(rs>512ULL*1024*1024)continue;
        for(uint64_t o=0;o<rs;o+=C){uint64_t tr=std::min((uint64_t)C,rs-o);
            mach_vm_size_t got=0;if(mach_vm_read_overwrite(g_task,r.s+o,tr,(vm_address_t)buf.data(),&got)!=KERN_SUCCESS)break;
            for(size_t i=0;i+8<=(size_t)got;i+=8){uint64_t v;memcpy(&v,buf.data()+i,8);
                if(v>=SMIN&&v<SMAX)h.push_back({r.s+o+i,v});}}}
    return h;
}

static std::string rstr(uint64_t pa){
    uint64_t s=spac(r64(pa));if(!vp(s))return"";
    uint32_t len=0;rmem(s+0x10,&len,4);if(!len||len>64)return"";
    std::string o;for(uint32_t i=0;i<len&&i<63;i++){
        uint16_t c=0;rmem(s+0x14+i*2,&c,2);if(!c)break;
        if(c>=32&&c<127)o+=(char)c;}
    return o.size()>=2?o:"";
}

static bool is_wp(float x,float y,float z){
    if(!std::isfinite(x)||!std::isfinite(y)||!std::isfinite(z))return false;
    if(x<-5000||x>5000||z<-5000||z>5000)return false;
    if(y<-500||y>3000)return false;
    return sqrtf(x*x+z*z)>15.0f;
}

struct Path{int off[4];
    bool operator<(const Path&o)const{
        for(int i=0;i<4;i++){if(off[i]!=o.off[i])return off[i]<o.off[i];}return false;}
};
struct PE{Path path;float x,y,z;};

static void sf(const uint8_t*b,int len,int o1,int o2,int o3,std::vector<PE>&out){
    for(int f=0;f+12<=len;f+=4){float x,y,z;
        memcpy(&x,b+f,4);memcpy(&y,b+f+4,4);memcpy(&z,b+f+8,4);
        if(!is_wp(x,y,z))continue;
        Path p;
        if(o2==-99)p={f,-1,-1,-1};
        else if(o3==-99)p={o1,f,-1,-1};
        else if(o3==-98)p={o1,o2,f,-1};
        else p={o1,o2,o3,f};
        out.push_back({p,x,y,z});}
}

static std::vector<PE> snap(uint64_t base,int osz){
    std::vector<PE> res;
    std::vector<uint8_t> b0(osz);
    if(!rmem(base,b0.data(),osz))return res;
    sf(b0.data(),osz,0,-99,-99,res);
    std::unordered_set<uint64_t> v1;
    for(int o1=0;o1+8<=osz;o1+=8){
        uint64_t p1;memcpy(&p1,b0.data()+o1,8);p1=spac(p1);
        if(!vp(p1)||v1.count(p1))continue;v1.insert(p1);
        uint8_t b1[0x500];if(!rmem(p1,b1,0x500))continue;
        sf(b1,0x500,o1,-99,-99,res);
        std::unordered_set<uint64_t> v2;
        for(int o2=0;o2+8<=0x200;o2+=8){
            uint64_t p2;memcpy(&p2,b1+o2,8);p2=spac(p2);
            if(!vp(p2)||v2.count(p2))continue;v2.insert(p2);
            uint8_t b2[0x400];if(!rmem(p2,b2,0x400))continue;
            sf(b2,0x400,o1,o2,-98,res);
            for(int o3=0;o3+8<=0x100;o3+=8){
                uint64_t p3;memcpy(&p3,b2+o3,8);p3=spac(p3);
                if(!vp(p3))continue;
                uint8_t b3[0x400];if(!rmem(p3,b3,0x400))continue;
                sf(b3,0x400,o1,o2,o3,res);}}}
    return res;
}

// =============================================================================
int main(){
    printf("\n  ╔═══════════════════════════════════════════════╗\n");
    printf("  ║  TRACE_POS v3 — m_CachedPtr Filter             ║\n");
    printf("  ║  Finds REAL BasePlayer, not items/deployables   ║\n");
    printf("  ╚═══════════════════════════════════════════════╝\n\n");

    pid_t pid=find_rust();
    if(pid<0){printf("[!] Rust not found\n");return 1;}
    printf("[+] Rust PID=%d\n",pid);
    if(task_for_pid(mach_task_self(),pid,&g_task)!=KERN_SUCCESS){
        printf("[!] task_for_pid failed\n");return 1;}
    enum_rg();
    printf("[+] %zu RW regions\n",g_rw.size());

    // Phase 1: Scan SteamIDs
    printf("[*] Scanning SteamIDs...\n");
    auto hits=scan_sids();
    printf("[+] %zu SID hits\n",hits.size());

    // Unique SIDs
    std::unordered_map<uint64_t,std::vector<uint64_t>> sid_addrs;
    for(auto&h:hits) sid_addrs[h.sid].push_back(h.addr);
    printf("[+] %zu unique SIDs\n\n",sid_addrs.size());

    // =========================================================================
    // Phase 2: Filter for objects with valid m_CachedPtr at +0x10
    // Real managed IL2CPP objects (BasePlayer) have this, items don't.
    // =========================================================================
    printf("[*] Filtering for objects with valid m_CachedPtr...\n");

    struct Candidate {
        uint64_t base, sid, vtable, cached_ptr;
        int sid_off;
    };
    std::vector<Candidate> candidates;

    for(auto& [sid, addrs] : sid_addrs) {
        for(auto addr : addrs) {
            // Try SID offsets from 0x100 to 0xA00
            for(int soff=0x100; soff<=0xA00; soff+=0x08) {
                uint64_t base = addr - soff;
                uint64_t vt = spac(r64(base));
                if(!vp(vt)) continue;
                // Check m_CachedPtr at +0x10
                uint64_t cp = spac(r64(base + 0x10));
                if(!vp(cp)) continue;
                // Also verify: m_CachedPtr should point to readable memory
                uint64_t test = 0;
                if(!rmem(cp, &test, 8)) continue;
                candidates.push_back({base, sid, vt, cp, soff});
            }
            // Also try +0x18 for m_CachedPtr (some IL2CPP versions)
            for(int soff=0x100; soff<=0xA00; soff+=0x08) {
                uint64_t base = addr - soff;
                uint64_t vt = spac(r64(base));
                if(!vp(vt)) continue;
                uint64_t cp = spac(r64(base + 0x18));
                if(!vp(cp)) continue;
                uint64_t test = 0;
                if(!rmem(cp, &test, 8)) continue;
                // Don't double-count if +0x10 was already valid
                uint64_t cp10 = spac(r64(base + 0x10));
                if(vp(cp10)) continue;
                candidates.push_back({base, sid, vt, cp, soff});
            }
        }
    }

    printf("[+] %zu candidates with valid m_CachedPtr\n", candidates.size());

    if(candidates.empty()) {
        printf("\n[!] No objects with valid m_CachedPtr found.\n");
        printf("[*] Falling back: scanning ALL vtable groups...\n\n");

        // Fallback: just show all groups so the user can choose
        struct VtGrp { uint64_t vt; int soff, cnt; };
        std::map<std::pair<uint64_t,int>,int> vm;
        for(auto& [sid,addrs]:sid_addrs){
            for(int soff=0x10;soff<=0xA00;soff+=0x08){
                uint64_t base=addrs[0]-soff;
                uint64_t vt=spac(r64(base));
                if(vp(vt))vm[{vt,soff}]++;}}
        std::vector<VtGrp> grps;
        for(auto& [k,c]:vm) if(c>=3) grps.push_back({k.first,k.second,c});
        std::sort(grps.begin(),grps.end(),[](auto&a,auto&b){return a.cnt>b.cnt;});

        printf("=== All Vtable Groups ===\n");
        for(size_t i=0;i<grps.size()&&i<20;i++){
            auto&g=grps[i];
            // Sample: check m_CachedPtr at +0x10 for a few
            int valid_cp=0;
            int checked=0;
            for(auto& [sid,addrs]:sid_addrs){
                if(checked>=5)break;
                uint64_t base=addrs[0]-g.soff;
                uint64_t vt=spac(r64(base));
                if(vt!=g.vt)continue;
                checked++;
                uint64_t cp=spac(r64(base+0x10));
                if(vp(cp))valid_cp++;
            }
            // Sample name
            std::string nm;
            for(auto& [sid,addrs]:sid_addrs){
                uint64_t base=addrs[0]-g.soff;
                uint64_t vt=spac(r64(base));
                if(vt!=g.vt)continue;
                for(int no:{0x18,0x20,0x28,0x2B0,0x2D8,0x660,0x690}){
                    nm=rstr(base+no);if(!nm.empty())break;}
                break;
            }
            printf("  vt=0x%llx  soff=+0x%x  cnt=%d  cachedPtr=%d/%d valid  name=\"%s\"\n",
                   g.vt, g.soff, g.cnt, valid_cp, checked, nm.c_str());
        }
        printf("\n[!] None have valid m_CachedPtr. This means the real BasePlayer\n");
        printf("    objects may not have been found via SteamID scan.\n");
        printf("    Possible reasons:\n");
        printf("    1. BasePlayer.userID is not in the standard SteamID64 range\n");
        printf("    2. The SteamID is obfuscated/encrypted\n");
        printf("    3. The managed BasePlayer object is in a non-standard heap region\n");
        return 1;
    }

    // Group candidates by (vtable, sid_off)
    std::map<std::pair<uint64_t,int>, std::vector<Candidate*>> groups;
    for(auto& c : candidates) groups[{c.vtable, c.sid_off}].push_back(&c);

    printf("\n=== Groups with valid m_CachedPtr ===\n");
    std::vector<std::pair<std::pair<uint64_t,int>, std::vector<Candidate*>*>> sorted_groups;
    for(auto& [k,v] : groups) sorted_groups.push_back({k, &v});
    std::sort(sorted_groups.begin(), sorted_groups.end(),
              [](auto&a,auto&b){return a.second->size()>b.second->size();});

    for(size_t i=0; i<sorted_groups.size() && i<10; i++) {
        auto& [key, vec] = sorted_groups[i];
        // Deduplicate by SID
        std::unordered_set<uint64_t> seen_sids;
        int unique = 0;
        for(auto* c : *vec) {
            if(!seen_sids.count(c->sid)){seen_sids.insert(c->sid);unique++;}
        }
        // Sample name
        std::string nm;
        for(auto* c : *vec) {
            for(int no : {0x18,0x20,0x28,0x2B0,0x2B8,0x2D0,0x2D8,0x660,0x690}) {
                nm = rstr(c->base + no);
                if(!nm.empty()) break;
            }
            if(!nm.empty()) break;
        }
        printf("  vt=0x%llx  SID=+0x%x  count=%zu  unique_sids=%d  name=\"%s\"\n",
               key.first, key.second, vec->size(), unique, nm.c_str());
    }

    // Pick the best group (most unique SIDs, prefer non-item names)
    auto& best = *sorted_groups[0].second;
    auto best_key = sorted_groups[0].first;

    // Collect unique players from best group
    struct PlayerObj { uint64_t base, sid, cached_ptr; };
    std::vector<PlayerObj> players;
    {
        std::unordered_set<uint64_t> seen;
        for(auto* c : best) {
            if(!seen.count(c->sid)) {
                seen.insert(c->sid);
                players.push_back({c->base, c->sid, c->cached_ptr});
            }
        }
    }

    printf("\n[+] Selected: vt=0x%llx  SID=+0x%x  %zu players\n",
           best_key.first, best_key.second, players.size());

    // Find name offset
    int name_off=-1;
    {std::map<int,int> sc;int lim=std::min((int)players.size(),20);
        for(int off=0x10;off<0xA00;off+=8)
            for(int i=0;i<lim;i++){
                std::string s=rstr(players[i].base+off);
                if(s.size()>=2&&s.size()<=32)sc[off]++;}
        int bs=0;for(auto&[o,c]:sc)if(c>bs){bs=c;name_off=o;}}

    printf("\n=== Players ===\n");
    for(size_t i=0;i<players.size()&&i<30;i++){
        std::string nm=(name_off>=0)?rstr(players[i].base+name_off):"";
        printf("  [%2zu] SID=...%04llu  base=0x%llx  native=0x%llx  %s\n",
               i, players[i].sid%10000, players[i].base, players[i].cached_ptr,
               nm.empty()?"(no name)":nm.c_str());
    }

    // =========================================================================
    // Phase 3: Deep walk + delta from BOTH managed object AND native object
    // =========================================================================
    int obj_size = std::max(0xA00, best_key.second + 0x200);
    obj_size = std::min(obj_size, 0x1000);
    int n_scan = std::min((int)players.size(), 6);

    printf("\n[*] Snapshot 1 (%d players)...\n", n_scan);

    // Snapshot from BOTH the managed object and the native (m_CachedPtr) object
    std::vector<std::map<Path, PE>> snap1_managed(n_scan);
    std::vector<std::map<Path, PE>> snap1_native(n_scan);

    for(int i=0;i<n_scan;i++){
        // Managed object walk
        auto em = snap(players[i].base, obj_size);
        for(auto&e:em) snap1_managed[i][e.path]=e;

        // Native object walk (from m_CachedPtr)
        auto en = snap(players[i].cached_ptr, 0x800);
        for(auto&e:en) snap1_native[i][e.path]=e;

        printf("  Player %d: %zu managed + %zu native candidates\n",
               i, em.size(), en.size());
    }

    printf("\n  ┌─────────────────────────────────────────────────┐\n");
    printf("  │  BOUGE-TOI EN JEU ! (8 secondes)                 │\n");
    printf("  └─────────────────────────────────────────────────┘\n");
    printf("  Countdown: ");fflush(stdout);
    for(int t=8;t>0;t--){printf("%d.. ",t);fflush(stdout);sleep(1);}
    printf("GO!\n\n");

    printf("[*] Snapshot 2...\n\n");
    int total=0;

    // Check managed objects
    for(int i=0;i<n_scan;i++){
        auto em2 = snap(players[i].base, obj_size);
        int pc=0;
        for(auto&e2:em2){
            auto it=snap1_managed[i].find(e2.path);
            if(it==snap1_managed[i].end())continue;
            auto&e1=it->second;
            float dx=e2.x-e1.x,dy=e2.y-e1.y,dz=e2.z-e1.z;
            float d=sqrtf(dx*dx+dy*dy+dz*dz);
            if(d<0.3f||d>200.0f)continue;
            total++;pc++;
            if(pc<=5){
                printf("  [MANAGED] Player %d (SID ...%04llu)\n",i,players[i].sid%10000);
                auto&p=e2.path;
                if(p.off[1]==-1)printf("    Path: base+0x%x\n",p.off[0]);
                else if(p.off[2]==-1)printf("    Path: base[+0x%x]->+0x%x\n",p.off[0],p.off[1]);
                else if(p.off[3]==-1)printf("    Path: base[+0x%x]->[+0x%x]->+0x%x\n",p.off[0],p.off[1],p.off[2]);
                else printf("    Path: base[+0x%x]->[+0x%x]->[+0x%x]->+0x%x\n",p.off[0],p.off[1],p.off[2],p.off[3]);
                printf("    (%.1f,%.1f,%.1f)->(%.1f,%.1f,%.1f) d=%.1fm\n",
                       e1.x,e1.y,e1.z,e2.x,e2.y,e2.z,d);
                // Debug pointers
                printf("    [Ptrs]");
                if(p.off[1]!=-1){uint64_t p1=spac(r64(players[i].base+p.off[0]));printf(" ->0x%llx",p1);
                    if(p.off[2]!=-1){uint64_t p2=spac(r64(p1+p.off[1]));printf(" ->0x%llx",p2);
                        if(p.off[3]!=-1){uint64_t p3=spac(r64(p2+p.off[2]));printf(" ->0x%llx",p3);}}}
                printf("\n\n");
            }
        }
        if(pc>5) printf("  ... +%d more managed changes for player %d\n\n",pc-5,i);
    }

    // Check native objects
    for(int i=0;i<n_scan;i++){
        auto en2 = snap(players[i].cached_ptr, 0x800);
        int pc=0;
        for(auto&e2:en2){
            auto it=snap1_native[i].find(e2.path);
            if(it==snap1_native[i].end())continue;
            auto&e1=it->second;
            float dx=e2.x-e1.x,dy=e2.y-e1.y,dz=e2.z-e1.z;
            float d=sqrtf(dx*dx+dy*dy+dz*dz);
            if(d<0.3f||d>200.0f)continue;
            total++;pc++;
            if(pc<=5){
                printf("  [NATIVE] Player %d (SID ...%04llu) native=0x%llx\n",
                       i,players[i].sid%10000,players[i].cached_ptr);
                auto&p=e2.path;
                if(p.off[1]==-1)printf("    Path: native+0x%x\n",p.off[0]);
                else if(p.off[2]==-1)printf("    Path: native[+0x%x]->+0x%x\n",p.off[0],p.off[1]);
                else if(p.off[3]==-1)printf("    Path: native[+0x%x]->[+0x%x]->+0x%x\n",p.off[0],p.off[1],p.off[2]);
                else printf("    Path: native[+0x%x]->[+0x%x]->[+0x%x]->+0x%x\n",p.off[0],p.off[1],p.off[2],p.off[3]);
                printf("    (%.1f,%.1f,%.1f)->(%.1f,%.1f,%.1f) d=%.1fm\n",
                       e1.x,e1.y,e1.z,e2.x,e2.y,e2.z,d);
                printf("    [Ptrs]");
                if(p.off[1]!=-1){uint64_t p1=spac(r64(players[i].cached_ptr+p.off[0]));printf(" ->0x%llx",p1);
                    if(p.off[2]!=-1){uint64_t p2=spac(r64(p1+p.off[1]));printf(" ->0x%llx",p2);
                        if(p.off[3]!=-1){uint64_t p3=spac(r64(p2+p.off[2]));printf(" ->0x%llx",p3);}}}
                printf("\n\n");
            }
        }
        if(pc>5) printf("  ... +%d more native changes for player %d\n\n",pc-5,i);
    }

    printf("  ══════════════════════════════════════════════════\n");
    printf("  Total changes: %d\n",total);
    printf("  ══════════════════════════════════════════════════\n");

    if(total==0){
        printf("\n[!] No changes detected.\n");
        printf("    -> Tu as bouge pendant les 8 secondes ?\n");
        printf("    -> Relance et BOUGE des le countdown!\n");
    } else {
        printf("\n  Use the chain info above to update radar.cpp\n");
    }

    return 0;
}
