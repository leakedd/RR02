// =============================================================================
// find_baseplayer.cpp — Find REAL BasePlayer objects by class name
//
// Strategy:
// 1. Scan for the C string "BasePlayer" in memory
// 2. Find the Il2CppClass that references this string (the klass metadata)
// 3. Scan heap for managed objects whose +0x00 equals this klass
// 4. Filter: only keep objects in HEAP (RW) regions with valid m_CachedPtr
// 5. Read SteamID, name, and position for each
//
// Compile: c++ -O2 -std=c++17 -o find_baseplayer find_baseplayer.cpp
// Run:     sudo ./find_baseplayer
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
static bool rmem(uint64_t a,void*b,size_t s){
    vm_size_t g=0;return vm_read_overwrite(g_task,(vm_address_t)a,s,(vm_address_t)b,&g)==KERN_SUCCESS&&(size_t)g==s;}
static uint64_t r64(uint64_t a){uint64_t v=0;rmem(a,&v,8);return v;}
static float rf(uint64_t a){float v=0;rmem(a,&v,4);return v;}
static uint64_t spac(uint64_t p){return p&0x0000FFFFFFFFFFFFULL;}
static bool vp(uint64_t p){uint64_t s=spac(p);return s>0x10000ULL&&s<0x7FFFFFFFFFFFULL;}

static pid_t find_rust(){
    pid_t pids[8192];int n=proc_listpids(PROC_ALL_PIDS,0,pids,sizeof(pids));
    for(int i=0;i<n/(int)sizeof(pid_t);i++){
        if(!pids[i])continue;char path[PROC_PIDPATHINFO_MAXSIZE]={};
        if(proc_pidpath(pids[i],path,sizeof(path))>0&&strstr(path,"Rust"))return pids[i];}
    return -1;
}

struct Rg{uint64_t s,e;uint32_t prot;};
static std::vector<Rg> g_all, g_rw, g_ro;

static void enum_rg(){
    mach_vm_address_t a=0;mach_vm_size_t sz;vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt;mach_port_t obj;
    while(true){cnt=VM_REGION_BASIC_INFO_COUNT_64;
        if(mach_vm_region(g_task,&a,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&cnt,&obj)!=KERN_SUCCESS)break;
        uint32_t p=info.protection;
        g_all.push_back({a,a+sz,p});
        if((p&VM_PROT_READ)&&(p&VM_PROT_WRITE)) g_rw.push_back({a,a+sz,p});
        if((p&VM_PROT_READ)&&!(p&VM_PROT_WRITE)) g_ro.push_back({a,a+sz,p});
        a+=sz;}
}

// Read C string from memory
static std::string read_cstr(uint64_t addr, int maxlen=128) {
    char buf[256]={};
    if(!rmem(addr, buf, std::min(maxlen, 255))) return "";
    buf[255]=0;
    return std::string(buf);
}

// Read IL2CPP managed string
static std::string read_il2str(uint64_t ptr_addr) {
    uint64_t s=spac(r64(ptr_addr));if(!vp(s))return"";
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

// Path through pointer chain (4 offsets max)
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
    printf("  ║  find_baseplayer — Find by IL2CPP Class Name    ║\n");
    printf("  ╚═══════════════════════════════════════════════╝\n\n");

    pid_t pid=find_rust();
    if(pid<0){printf("[!] Rust not found\n");return 1;}
    printf("[+] Rust PID=%d\n",pid);
    if(task_for_pid(mach_task_self(),pid,&g_task)!=KERN_SUCCESS){
        printf("[!] task_for_pid failed\n");return 1;}
    enum_rg();
    printf("[+] %zu RW, %zu RO, %zu total regions\n",g_rw.size(),g_ro.size(),g_all.size());

    // =========================================================================
    // Step 1: Find "BasePlayer\0" string in memory
    // =========================================================================
    printf("\n[*] Scanning for \"BasePlayer\" string...\n");

    const char* target = "BasePlayer";
    int tlen = strlen(target);
    std::vector<uint64_t> string_addrs;

    const size_t CHUNK = 4*1024*1024;
    std::vector<uint8_t> buf(CHUNK);

    // Scan ALL readable regions for the string
    for(auto& rg : g_all) {
        uint64_t rsz = rg.e - rg.s;
        if(rsz > 512ULL*1024*1024) continue;
        for(uint64_t off=0; off<rsz; off+=CHUNK) {
            uint64_t toread = std::min((uint64_t)CHUNK, rsz-off);
            mach_vm_size_t got=0;
            if(mach_vm_read_overwrite(g_task, rg.s+off, toread,
                                       (vm_address_t)buf.data(), &got)!=KERN_SUCCESS) break;
            for(size_t i=0; i+tlen+1<=(size_t)got; i++) {
                if(memcmp(buf.data()+i, target, tlen)==0 && buf[i+tlen]==0) {
                    // Found "BasePlayer\0"
                    // Filter: the byte BEFORE should not be alphanumeric
                    // (to avoid matching "SomeBasePlayer")
                    if(i > 0 && ((buf[i-1]>='A'&&buf[i-1]<='Z') ||
                                 (buf[i-1]>='a'&&buf[i-1]<='z'))) continue;
                    string_addrs.push_back(rg.s + off + i);
                }
            }
        }
    }
    printf("[+] Found \"BasePlayer\" at %zu addresses\n", string_addrs.size());
    for(size_t i=0; i<string_addrs.size() && i<10; i++)
        printf("    0x%llx\n", string_addrs[i]);

    // =========================================================================
    // Step 2: Find Il2CppClass that points to this string
    // The Il2CppClass has a name pointer at various offsets depending on version.
    // We scan for pointers to our string addresses.
    // =========================================================================
    printf("\n[*] Finding Il2CppClass referencing \"BasePlayer\"...\n");

    std::vector<uint64_t> klass_candidates;

    // For each string address, scan memory for pointers to it
    for(auto str_addr : string_addrs) {
        // Scan RO regions first (klass metadata is usually read-only)
        for(auto& rg : g_ro) {
            uint64_t rsz = rg.e - rg.s;
            if(rsz > 64*1024*1024) continue; // klass metadata regions are small
            for(uint64_t off=0; off<rsz; off+=CHUNK) {
                uint64_t toread = std::min((uint64_t)CHUNK, rsz-off);
                mach_vm_size_t got=0;
                if(mach_vm_read_overwrite(g_task, rg.s+off, toread,
                                           (vm_address_t)buf.data(), &got)!=KERN_SUCCESS) break;
                for(size_t i=0; i+8<=(size_t)got; i+=8) {
                    uint64_t v; memcpy(&v, buf.data()+i, 8);
                    if(v == str_addr) {
                        // Found a pointer to "BasePlayer" string
                        // The Il2CppClass.name field could be at various offsets
                        // Common: +0x10, +0x18, +0x48
                        // So the klass base is at ptr_addr - name_offset
                        uint64_t ptr_addr = rg.s + off + i;
                        for(int noff : {0x10, 0x18, 0x48, 0x08, 0x20}) {
                            uint64_t kb = ptr_addr - noff;
                            // Verify: klass should have valid pointers
                            uint64_t f0 = spac(r64(kb));
                            uint64_t f8 = spac(r64(kb+8));
                            if(vp(f0) || vp(f8)) {
                                klass_candidates.push_back(kb);
                            }
                        }
                    }
                }
            }
        }
    }

    // Deduplicate
    std::sort(klass_candidates.begin(), klass_candidates.end());
    klass_candidates.erase(std::unique(klass_candidates.begin(), klass_candidates.end()),
                           klass_candidates.end());
    printf("[+] %zu klass candidates\n", klass_candidates.size());

    // =========================================================================
    // Step 3: For each klass candidate, scan HEAP for objects with that klass
    // =========================================================================
    printf("\n[*] Scanning heap for BasePlayer instances...\n");

    struct PlayerObj {
        uint64_t addr;
        uint64_t klass;
        uint64_t cached_ptr;
    };

    std::vector<PlayerObj> players;

    for(auto klass : klass_candidates) {
        // Scan RW (heap) regions for objects whose +0x00 == klass
        int found = 0;
        for(auto& rg : g_rw) {
            uint64_t rsz = rg.e - rg.s;
            if(rsz > 256ULL*1024*1024) continue;
            for(uint64_t off=0; off<rsz; off+=CHUNK) {
                uint64_t toread = std::min((uint64_t)CHUNK, rsz-off);
                mach_vm_size_t got=0;
                if(mach_vm_read_overwrite(g_task, rg.s+off, toread,
                                           (vm_address_t)buf.data(), &got)!=KERN_SUCCESS) break;
                for(size_t i=0; i+8<=(size_t)got; i+=8) {
                    uint64_t v; memcpy(&v, buf.data()+i, 8);
                    if(v == klass) {
                        uint64_t obj_addr = rg.s + off + i;
                        // Check m_CachedPtr at +0x10
                        uint64_t cp = spac(r64(obj_addr + 0x10));
                        if(vp(cp)) {
                            players.push_back({obj_addr, klass, cp});
                            found++;
                        }
                    }
                }
            }
        }
        if(found > 0) {
            printf("  klass=0x%llx -> %d objects with valid m_CachedPtr\n", klass, found);
        }
    }

    printf("\n[+] Total: %zu BasePlayer objects found\n", players.size());

    if(players.empty()) {
        printf("[!] No BasePlayer objects found.\n");
        printf("    The Il2CppClass name offset might be non-standard.\n");
        printf("    Trying alternative: scan for pointers to ALL \"BasePlayer\" strings\n");
        printf("    in ALL regions (not just read-only)...\n\n");

        // Extended scan: also check RW regions for klass
        for(auto str_addr : string_addrs) {
            for(auto& rg : g_rw) {
                uint64_t rsz = rg.e - rg.s;
                if(rsz > 64*1024*1024) continue;
                for(uint64_t off=0; off<rsz; off+=CHUNK) {
                    uint64_t toread = std::min((uint64_t)CHUNK, rsz-off);
                    mach_vm_size_t got=0;
                    if(mach_vm_read_overwrite(g_task, rg.s+off, toread,
                                               (vm_address_t)buf.data(), &got)!=KERN_SUCCESS) break;
                    for(size_t i=0; i+8<=(size_t)got; i+=8) {
                        uint64_t v; memcpy(&v, buf.data()+i, 8);
                        if(v == str_addr) {
                            uint64_t ptr_addr = rg.s + off + i;
                            for(int noff : {0x10, 0x18, 0x48, 0x08, 0x20}) {
                                uint64_t kb = ptr_addr - noff;
                                klass_candidates.push_back(kb);
                            }
                        }
                    }
                }
            }
        }
        std::sort(klass_candidates.begin(), klass_candidates.end());
        klass_candidates.erase(std::unique(klass_candidates.begin(), klass_candidates.end()),
                               klass_candidates.end());
        printf("[+] Extended: %zu klass candidates\n", klass_candidates.size());

        for(auto klass : klass_candidates) {
            int found=0;
            for(auto& rg : g_rw) {
                uint64_t rsz=rg.e-rg.s;if(rsz>256ULL*1024*1024)continue;
                for(uint64_t off=0;off<rsz;off+=CHUNK){
                    uint64_t toread=std::min((uint64_t)CHUNK,rsz-off);
                    mach_vm_size_t got=0;
                    if(mach_vm_read_overwrite(g_task,rg.s+off,toread,(vm_address_t)buf.data(),&got)!=KERN_SUCCESS)break;
                    for(size_t i=0;i+8<=(size_t)got;i+=8){
                        uint64_t v;memcpy(&v,buf.data()+i,8);
                        if(v==klass){uint64_t oa=rg.s+off+i;
                            uint64_t cp=spac(r64(oa+0x10));
                            if(vp(cp)){players.push_back({oa,klass,cp});found++;}}}}
            }
            if(found>0) printf("  klass=0x%llx -> %d objects\n",klass,found);
        }
        printf("[+] Extended total: %zu objects\n",players.size());
    }

    if(players.empty()){
        printf("[!] Still no BasePlayer objects. Game might use obfuscated class names.\n");
        return 1;
    }

    // =========================================================================
    // Step 4: Analyze BasePlayer objects — find SteamID, name, and position
    // =========================================================================
    printf("\n=== BasePlayer Objects ===\n");

    // For each player, scan for SteamID and name in the object
    static const uint64_t SMIN=76561198000000000ULL, SMAX=76561200000000000ULL;

    for(size_t pi=0; pi<players.size() && pi<30; pi++) {
        auto& p = players[pi];
        printf("\n  [%zu] addr=0x%llx  klass=0x%llx  native=0x%llx\n",
               pi, p.addr, p.klass, p.cached_ptr);

        // Read 0x1000 bytes of the object
        uint8_t obj[0x1000];
        if(!rmem(p.addr, obj, 0x1000)) { printf("    (unreadable)\n"); continue; }

        // Find SteamID
        for(int off=0x10; off<0xF00; off+=8) {
            uint64_t v; memcpy(&v, obj+off, 8);
            if(v>=SMIN && v<SMAX) {
                printf("    SteamID at +0x%x: %llu\n", off, v);
            }
        }

        // Find name (IL2CPP string)
        for(int off=0x10; off<0x800; off+=8) {
            std::string nm = read_il2str(p.addr + off);
            if(nm.size()>=2 && nm.size()<=32) {
                printf("    Name at +0x%x: \"%s\"\n", off, nm.c_str());
            }
        }

        // Find world-position floats directly in the object
        printf("    Positions (direct):\n");
        int pos_count = 0;
        for(int off=0x10; off<0xF00 && pos_count<5; off+=4) {
            float x,y,z;
            memcpy(&x,obj+off,4);memcpy(&y,obj+off+4,4);memcpy(&z,obj+off+8,4);
            if(is_wp(x,y,z)) {
                printf("      +0x%x: (%.1f, %.1f, %.1f)\n", off, x, y, z);
                pos_count++;
            }
        }
    }

    // =========================================================================
    // Step 5: Deep walk + delta for position finding
    // =========================================================================
    if(players.size() == 0) return 1;

    int n_scan = std::min((int)players.size(), 4);
    printf("\n[*] Snapshot 1 from native objects (%d players)...\n", n_scan);

    std::vector<std::map<Path,PE>> snap1(n_scan);
    for(int i=0;i<n_scan;i++){
        auto es = snap(players[i].cached_ptr, 0x800);
        for(auto&e:es) snap1[i][e.path]=e;
        // Also walk managed object
        auto em = snap(players[i].addr, 0x1000);
        for(auto&e:em) {
            Path mp = e.path;
            // Shift offsets to distinguish from native: add 0x10000
            mp.off[0] += 0x10000;
            snap1[i][mp] = e;
        }
        printf("  Player %d: %zu total candidates\n", i, snap1[i].size());
    }

    printf("\n  ┌─────────────────────────────────────────────────┐\n");
    printf("  │  BOUGE-TOI EN JEU ! (8 secondes)                 │\n");
    printf("  └─────────────────────────────────────────────────┘\n");
    printf("  Countdown: ");fflush(stdout);
    for(int t=8;t>0;t--){printf("%d.. ",t);fflush(stdout);sleep(1);}
    printf("GO!\n\n");

    printf("[*] Snapshot 2...\n");
    int total=0;

    for(int i=0;i<n_scan;i++){
        auto es2 = snap(players[i].cached_ptr, 0x800);
        auto em2 = snap(players[i].addr, 0x1000);

        // Combine
        std::vector<PE> all2;
        for(auto&e:es2) all2.push_back(e);
        for(auto&e:em2) {
            PE me = e;
            me.path.off[0] += 0x10000;
            all2.push_back(me);
        }

        int pc=0;
        for(auto&e2:all2){
            auto it=snap1[i].find(e2.path);
            if(it==snap1[i].end())continue;
            auto&e1=it->second;
            float dx=e2.x-e1.x,dy=e2.y-e1.y,dz=e2.z-e1.z;
            float d=sqrtf(dx*dx+dy*dy+dz*dz);
            if(d<0.3f||d>200.0f)continue;
            total++;pc++;
            bool is_native = e2.path.off[0] < 0x10000;
            if(pc<=8){
                printf("\n  [%s] Player %d\n", is_native?"NATIVE":"MANAGED", i);
                auto p = e2.path;
                if(!is_native) p.off[0] -= 0x10000;
                if(p.off[1]==-1) printf("    %s+0x%x\n", is_native?"native":"base", p.off[0]);
                else if(p.off[2]==-1) printf("    %s[+0x%x]->+0x%x\n", is_native?"native":"base", p.off[0],p.off[1]);
                else if(p.off[3]==-1) printf("    %s[+0x%x]->[+0x%x]->+0x%x\n", is_native?"native":"base", p.off[0],p.off[1],p.off[2]);
                else printf("    %s[+0x%x]->[+0x%x]->[+0x%x]->+0x%x\n", is_native?"native":"base", p.off[0],p.off[1],p.off[2],p.off[3]);
                printf("    (%.1f,%.1f,%.1f)->(%.1f,%.1f,%.1f) d=%.1fm\n",
                       e1.x,e1.y,e1.z,e2.x,e2.y,e2.z,d);
            }
        }
        if(pc>8)printf("  ... +%d more for player %d\n",pc-8,i);
    }

    printf("\n  ══════════════════════════════════════════════════\n");
    printf("  Total: %d changes\n",total);
    printf("  ══════════════════════════════════════════════════\n");

    return 0;
}
