// ============================================================================
// RR02 radar_daemon v18 — CIBLÉ GameAssembly.dylib + Static Fields
// Trouve GameAssembly.dylib en mémoire, calcule les adresses absolues,
// lit les listes de joueurs via les static fields de BaseNetworkable.
// ============================================================================
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <cstdlib>
#include <unistd.h>
#include <vector>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>
#include <mach-o/loader.h>

static task_t g_task;
static int    g_pid = -1;
static uint64_t g_gameassembly_base = 0;

// --- helpers mémoire ---
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

// --- Trouver GameAssembly.dylib en mémoire ---
static bool find_gameassembly(){
    mach_vm_address_t a=0; mach_vm_size_t sz;
    vm_region_basic_info_data_64_t info; mach_msg_type_number_t cnt=VM_REGION_BASIC_INFO_COUNT_64; mach_port_t obj;
    while(mach_vm_region(g_task,&a,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&cnt,&obj)==KERN_SUCCESS){
        if(!(info.protection&VM_PROT_READ)){a+=sz;continue;}
        if(a>0x400000000ULL)break;
        // Chercher magic Mach-O arm64 (0xFEEDFACF)
        uint32_t magic=0; mach_vm_size_t got;
        if(mach_vm_read_overwrite(g_task,a,4,(vm_address_t)&magic,&got)==KERN_SUCCESS){
            if(magic==0xFEEDFACF){
                g_gameassembly_base=a;
                printf("[+] GameAssembly.dylib base: 0x%llx\n", a);
                return true;
            }
        }
        a+=sz;
    }
    return false;
}

// --- Position via Transform (Model.rootBone -> position) ---
static bool read_transform_pos(uint64_t transform, float& x, float& y, float& z){
    if(transform<0x1000||transform>0x7FFFFFFFFFFFULL)return false;
    // Unity ARM64 IL2CPP: position à Transform+0x10 (ou 0x20)
    uint64_t candidates[] = {0x10, 0x20, 0x30};
    for(uint64_t off : candidates){
        x=rf(transform+off); y=rf(transform+off+4); z=rf(transform+off+8);
        if(valid_world(x,y,z)) return true;
    }
    return false;
}

static bool read_entity_pos(uint64_t entity, float& x, float& y, float& z){
    // BaseEntity.model = 0x1B8 -> Model.rootBone = 0x8 -> Transform.position
    uint64_t model_ptr = r64d(entity + 0x1B8);
    if(model_ptr>0x1000 && model_ptr<0x7FFFFFFFFFFFULL){
        uint64_t rootBone = r64d(model_ptr + 0x8);
        if(rootBone>0x1000 && rootBone<0x7FFFFFFFFFFFULL){
            if(read_transform_pos(rootBone, x, y, z)) return true;
        }
    }
    // Fallback: Bounds.center = entity + 0x18C
    x=rf(entity+0x18C); y=rf(entity+0x18C+4); z=rf(entity+0x18C+8);
    return valid_world(x,y,z);
}

// --- Lire un tableau d'objets (array IL2CPP) ---
// Structure: [length][elements...]
static int read_object_array(uint64_t array_addr, std::vector<uint64_t>& out){
    if(array_addr<0x1000||array_addr>0x7FFFFFFFFFFFULL)return 0;
    uint64_t length = r64d(array_addr);
    if(length==0||length>1000)return 0;
    for(uint64_t i=0;i<length;i++){
        uint64_t obj = r64d(array_addr + 8 + i*8);
        if(obj>0x1000 && obj<0x7FFFFFFFFFFFULL) out.push_back(obj);
    }
    return (int)length;
}

// --- Lire une List<T> IL2CPP ---
// List<T> : _items (array) + _size + _version
static int read_list_base(uint64_t list_addr, std::vector<uint64_t>& out){
    if(list_addr<0x1000||list_addr>0x7FFFFFFFFFFFULL)return 0;
    // List<T>._items est à list_addr + 0x10 (ou 0x18)
    uint64_t items = r64d(list_addr + 0x10);
    if(items<0x1000||items>0x7FFFFFFFFFFFULL)return 0;
    uint64_t size = r64d(list_addr + 0x18);
    if(size==0||size>1000)return 0;
    for(uint64_t i=0;i<size;i++){
        uint64_t obj = r64d(items + 8 + i*8);
        if(obj>0x1000 && obj<0x7FFFFFFFFFFFULL) out.push_back(obj);
    }
    return (int)size;
}

// --- Trouver les joueurs via les static fields ---
// BaseNetworkable a des static fields avec des listes d'entités
// On cherche dans le dump les RVA de ces champs
static void scan_players(std::vector<uint64_t>& players){
    // Les static fields sont dans la structure Il2CppClass.static_fields
    // Pour l'instant, on scan les régions de GameAssembly pour trouver
    // des pointeurs vers des BasePlayer valides
    
    // Approche: chercher les régions de heap de GameAssembly
    // et y trouver des objets BasePlayer (vtable check)
    mach_vm_address_t a=g_gameassembly_base; mach_vm_size_t sz;
    vm_region_basic_info_data_64_t info; mach_msg_type_number_t cnt=VM_REGION_BASIC_INFO_COUNT_64; mach_port_t obj;
    
    // Chercher dans les régions du heap (RW)
    while(mach_vm_region(g_task,&a,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&cnt,&obj)==KERN_SUCCESS){
        if(a>g_gameassembly_base+0x10000000ULL)break; // limite 256MB
        if(!(info.protection&VM_PROT_READ)){a+=sz;continue;}
        if(sz<0x10000){a+=sz;continue;}
        
        // Lire par blocs de 1MB
        std::vector<uint8_t> buf(1024*1024);
        for(uint64_t o=0;o<sz;o+=buf.size()){
            uint64_t tr=std::min((uint64_t)buf.size(),sz-o);
            mach_vm_size_t got=0;
            if(mach_vm_read_overwrite(g_task,a+o,tr,(vm_address_t)buf.data(),&got)!=KERN_SUCCESS)continue;
            for(size_t i=0;i+8<=(size_t)got;i+=8){
                uint64_t v; memcpy(&v,buf.data()+i,8);
                // Vérifier si c'est un pointeur vers un BasePlayer valide
                if(v<0x1000||v>0x7FFFFFFFFFFFULL)continue;
                // Vérifier si c'est un objet IL2CPP (vtable pointe vers GameAssembly)
                uint64_t vtable = r64d(v);
                if(vtable>g_gameassembly_base && vtable<g_gameassembly_base+0x10000000ULL){
                    // Vérifier si c'est un BasePlayer: lire model à 0x1B8
                    uint64_t model = r64d(v+0x1B8);
                    if(model>0x1000 && model<0x7FFFFFFFFFFFULL){
                        uint64_t rootBone = r64d(model+0x8);
                        if(rootBone>0x1000 && rootBone<0x7FFFFFFFFFFFULL){
                            // Vérifier que c'est un joueur (pas un autre BaseEntity)
                            // BasePlayer a un steamID quelque part
                            // Chercher un steamID dans les premiers 0x600 bytes
                            for(uint64_t k=0x100;k<0x600;k+=8){
                                uint64_t sid=r64d(v+k);
                                if(sid>76561198000000000ULL && sid<76561200000000000ULL){
                                    players.push_back(v);
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
        a+=sz;
    }
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
    if(task_for_pid(mach_task_self(),g_pid,&g_task)!=KERN_SUCCESS){printf("[!] task_for_pid failed\n");return 1;}
    printf("[+] RustClient pid=%d\n",g_pid);

    if(!find_gameassembly()){
        printf("[!] GameAssembly.dylib not found in memory\n");
        return 1;
    }

    int tick=0;
    while(true){
        tick++;
        std::vector<uint64_t> players;
        scan_players(players);
        
        // Dédupliquer
        std::sort(players.begin(), players.end());
        players.erase(std::unique(players.begin(), players.end()), players.end());
        
        printf("[tick=%d] %zu players found\n", tick, players.size());
        
        // Générer JSON
        std::string json="{\"players\":[";
        for(size_t i=0;i<players.size();i++){
            float x,y,z;
            if(!read_entity_pos(players[i],x,y,z)) continue;
            if(i>0) json+=",";
            json+="{\"x\":"+std::to_string(x)+",\"y\":"+std::to_string(y)+",\"z\":"+std::to_string(z)+"}";
        }
        json+="]}";
        write_json(json);
        
        sleep(1);
    }
    return 0;
}
