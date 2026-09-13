// ============================================================================
// RR02 radar_daemon v17 — OFFSET DIRECTS DEPUIS DUMP.CS
// Build 24614784, macOS ARM64. External only (task_for_pid, NO injection).
//
// Utilise les offsets r�els extraits du dump IL2CPP (version metadata 39):
//   BaseEntity.model         = 0x1B8  -> Model*
//   Model.rootBone           = 0x8    -> Transform*
//   Transform.position       = Unity standard (0x10 ou via Transform::get_position)
//
//   BaseCombatEntity.startHealth = 0x240 (float)
//
// Alternative rapide:
//   BaseEntity.bounds.center = 0x18C + 0x0 = position approx (Bounds)
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

static task_t g_task;
static int    g_pid = -1;

// --- helpers mémoire ---
static bool r64(uint64_t a, uint64_t& o){
    if(a<0x1000||a>0x7FFFFFFFFFFFULL)return false;
    mach_vm_size_t s; return mach_vm_read_overwrite(g_task,a,8,(vm_address_t)&o,&s)==KERN_SUCCESS;
}
static uint64_t r64d(uint64_t a){ uint64_t o=0; r64(a,o); return o; }
static float rf(uint64_t a){ float f=0; if(a<0x1000||a>0x7FFFFFFFFFFFULL)return 0;
    mach_vm_size_t s; mach_vm_read_overwrite(g_task,a,4,(vm_address_t)&f,&s); return f; }
static bool rf3(uint64_t a, float& x, float& y, float& z){
    if(a<0x1000||a>0x7FFFFFFFFFFFULL)return false;
    mach_vm_size_t s; return mach_vm_read_overwrite(g_task,a,12,(vm_address_t)&x,&s)==KERN_SUCCESS;
}

static bool valid_world(float x,float y,float z){
    return std::isfinite(x)&&std::isfinite(y)&&std::isfinite(z)
        &&std::fabs(x)>5.f&&std::fabs(z)>5.f
        &&std::fabs(x)<6000.f&&std::fabs(z)<6000.f
        &&y>-250.f&&y<1500.f;
}

// --- Scan m�moire: trouve tous les objets BaseEntity via leur mod�le ---
struct Entity { uint64_t base; uint64_t sid; uint64_t model; };
static std::vector<Entity> scan_entities(){
    std::vector<Entity> out;
    std::vector<uint8_t> buf(8*1024*1024);
    mach_vm_address_t a=0; mach_vm_size_t sz;
    vm_region_basic_info_data_64_t info; mach_msg_type_number_t cnt=VM_REGION_BASIC_INFO_COUNT_64; mach_port_t obj;
    std::map<uint64_t,uint64_t> by_sid;

    while(mach_vm_region(g_task,&a,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&cnt,&obj)==KERN_SUCCESS){
        if(!(info.protection&VM_PROT_READ)){a+=sz;continue;}
        if(a>0x400000000ULL)break;
        uint64_t rs=sz; if(rs>1024ULL*1024*1024||rs<0x4000){a+=sz;continue;}
        for(uint64_t o=0;o<rs;o+=buf.size()){
            uint64_t tr=std::min((uint64_t)buf.size(),rs-o);
            mach_vm_size_t got=0;
            if(tr<8)continue;
            if(mach_vm_read_overwrite(g_task,a+o,tr,(vm_address_t)buf.data(),&got)!=KERN_SUCCESS)continue;
            for(size_t i=0;i+8<=(size_t)got;i+=8){
                uint64_t v; memcpy(&v,buf.data()+i,8);
                if(v<SID_MIN||v>=SID_MAX)continue;
                if(by_sid.count(v))continue;
                uint64_t sid_addr=a+o+i;
                // Deviner l'objet: SID est typiquement � obj + offset, chercher obj qui contient ce SID
                // Essayer plusieurs offsets communs
                for(uint64_t k=0x100;k<=0x800;k+=8){
                    uint64_t cand=sid_addr-k;
                    if(r64d(cand+k)==v){
                        // V�rifier si c'est un BaseEntity valide: model � 0x1B8
                        uint64_t model_ptr=r64d(cand+0x1B8);
                        if(model_ptr>0x1000 && model_ptr<0x7FFFFFFFFFFFULL){
                            // V�rifier que rootBone existe
                            uint64_t rootBone=r64d(model_ptr+0x8);
                            if(rootBone>0x1000 && rootBone<0x7FFFFFFFFFFFULL){
                                by_sid[v]=cand;
                                break;
                            }
                        }
                    }
                }
            }
        }
        a+=sz;
    }
    for(auto& kv : by_sid) out.push_back({kv.second, kv.first, 0});
    return out;
}

// --- Position via Transform::get_position (appel Unity) ---
// Transform::get_position(Vector3& out) est une m�thode, mais on peut lire
// la position directement via les valeurs du Transform en m�moire.
// Sur IL2CPP/ARM64, la position est g�n�ralement � Transform + 0x10 (ou 0x20)
static bool read_transform_pos(uint64_t transform, float& x, float& y, float& z){
    if(transform<0x1000||transform>0x7FFFFFFFFFFFULL)return false;
    // Essayer plusieurs offsets courants pour Transform.position
    // Unity ARM64 IL2CPP: position typiquement � 0x10 ou 0x20
    uint64_t candidates[] = {0x10, 0x20, 0x30, 0x40};
    for(uint64_t off : candidates){
        x=rf(transform+off); y=rf(transform+off+4); z=rf(transform+off+8);
        if(valid_world(x,y,z)) return true;
    }
    return false;
}

// --- Position via Bounds.center (fallback) ---
static bool read_bounds_pos(uint64_t entity, float& x, float& y, float& z){
    // Bounds.center est � entity + 0x18C (Bounds struct, center au d�but)
    uint64_t bounds_addr = entity + 0x18C;
    x=rf(bounds_addr); y=rf(bounds_addr+4); z=rf(bounds_addr+8);
    return valid_world(x,y,z);
}

// --- Position distante: cha�ne model -> rootBone -> position ---
static bool read_entity_pos(uint64_t entity, float& x, float& y, float& z){
    // M�thode 1: via le mod�le et le transform
    uint64_t model_ptr = r64d(entity + 0x1B8);
    if(model_ptr>0x1000 && model_ptr<0x7FFFFFFFFFFFULL){
        uint64_t rootBone = r64d(model_ptr + 0x8);
        if(rootBone>0x1000 && rootBone<0x7FFFFFFFFFFFULL){
            if(read_transform_pos(rootBone, x, y, z)) return true;
        }
    }
    // M�thode 2: via bounds
    return read_bounds_pos(entity, x, y, z);
}

// --- Local player: trouver via un SID connu ou via le pattern ---
// Le local player a souvent des propri�t�s sp�cifiques. Pour l'instant,
// on utilise le scan SID et on suppose que le local est parmi les r�sultats.
static uint64_t g_local_entity = 0;
static uint64_t g_local_sid = 0;

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

    // Scan initial
    std::vector<Entity> entities = scan_entities();
    printf("[*] Scan: %zu entities found\n", entities.size());

    if(entities.empty()){
        printf("[!] Aucune entit� trouv�e. V�rifier que Rust est en jeu.\n");
        return 1;
    }

    // Prendre la premi�re comme "local" (temporaire - am�liorer avec un SID connu)
    g_local_entity = entities[0].base;
    g_local_sid = entities[0].sid;
    printf("[*] Local assumed: SID=%llu at 0x%llx\n", (unsigned long long)g_local_sid, (unsigned long long)g_local_entity);

    // Boucle principale
    int tick=0;
    while(true){
        tick++;
        if(tick%100==0){
            entities = scan_entities();  // refresh ~10s
        }

        float lx=0,ly=0,lz=0;
        bool local_ok = read_entity_pos(g_local_entity, lx, ly, lz);
        if(!local_ok && tick%50==0){
            printf("[!] Local pos lost, re-scanning...\n");
            entities = scan_entities();
            if(!entities.empty()){
                g_local_entity = entities[0].base;
                g_local_sid = entities[0].sid;
            }
        }

        std::string json="{\"local\":{\"x\":"+std::to_string(lx)+",\"y\":"+std::to_string(ly)+",\"z\":"+std::to_string(lz)+"},\"players\":[";
        bool first=true; int id=1;
        for(auto& e : entities){
            if(e.base==g_local_entity) continue;
            float x,y,z;
            if(!read_entity_pos(e.base,x,y,z)) continue;
            float d=std::sqrt((x-lx)*(x-lx)+(z-lz)*(z-lz));
            if(!first) json+=",";
            first=false;
            json+="{\"id\":"+std::to_string(id++)+",\"x\":"+std::to_string(x)+",\"y\":"+std::to_string(y)+",\"z\":"+std::to_string(z)+",\"dist\":"+std::to_string(d)+",\"sid\":"+std::to_string(e.sid)+"}";
        }
        json+="]}";
        write_json(json);

        if(tick%50==0){
            printf("  tick=%d entities=%zu local=(%.1f,%.1f,%.1f)\n", tick, entities.size(), lx, ly, lz);
        }
        usleep(100000);  // 10Hz
    }
    return 0;
}
