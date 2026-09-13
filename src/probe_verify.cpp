// probe_verify — valide la chaîne de position :
//   BaseEntity+0x1B8 -> Model ; Model+0x28 -> Transform IL2CPP ; +0x10 -> Transform natif ;
//   nat+0x28 -> struct ; +0x90 = Vector3 position monde.
// Contrôle : écart avec PlayerModel+0x2F8 (verité terrain) sur plusieurs joueurs.
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cmath>
#include <vector>
#include <string>
#include <algorithm>
#include <ctime>

static task_t T;
static bool rd(uint64_t a,void*b,size_t n){ mach_vm_size_t g=0;
    return mach_vm_read_overwrite(T,a,n,(mach_vm_address_t)b,&g)==KERN_SUCCESS && g==n; }
static uint64_t r64(uint64_t a){ uint64_t v=0; rd(a,&v,8); return v; }
static bool sane(const float*v){ return std::isfinite(v[0])&&std::isfinite(v[1])&&std::isfinite(v[2])
    && fabsf(v[0])<6000&&fabsf(v[2])<6000&&v[1]>0.3f&&v[1]<900; }
struct Reg{ uint64_t a,sz; }; static std::vector<Reg> R;
static void regions(){ mach_vm_address_t a=0x100000000ULL;
    for(;;){ mach_vm_address_t q=a; mach_vm_size_t sz=0; vm_region_basic_info_data_64_t bi; mach_port_t ob=0;
        mach_msg_type_number_t ci=VM_REGION_BASIC_INFO_COUNT_64;
        if(mach_vm_region(T,&q,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&bi,&ci,&ob)!=KERN_SUCCESS) break;
        if(sz>0&&(bi.protection&VM_PROT_READ)&&(bi.protection&VM_PROT_WRITE)) R.push_back({q,sz});
        if(q+sz<=a) break; a=q+sz; } }
// chaîne position
static bool chain_pos(uint64_t obj,float*out){
    uint64_t m=r64(obj+0x1B8); if(m<0x1000000) return false;
    uint64_t tr=r64(m+0x28); if(tr<0x1000000) return false;
    uint64_t nat=r64(tr+0x10); if(nat<0x1000000) return false;
    uint64_t d=r64(nat+0x28); if(d<0x1000000) return false;
    if(!rd(d+0x90,out,12)) return false;
    return sane(out);
}
struct Cls{ const char* n; uint64_t k; };
int main(){
    setvbuf(stdout,NULL,_IONBF,0);
    double t0=(double)clock()/CLOCKS_PER_SEC;
    pid_t PID=0; { FILE* f=popen("pgrep -x Rust | head -1","r"); char b[64]; if(f&&fgets(b,64,f)) PID=atoi(b); if(f)pclose(f); }
    if(!PID||task_for_pid(mach_task_self(),PID,&T)!=KERN_SUCCESS){ printf("task_for_pid KO\n"); return 1; }
    regions();
    Cls C[]={{"BasePlayer",0x10466cdb0ULL},{"PlayerModel",0x129a2abd0ULL},{"Model",0x12895e6e0ULL},
             {"PlayerCorpse",0x129b01530ULL},{"LootContainer",0x12868d200ULL},{"DroppedItem",0x10462f0f0ULL},
             {"DroppedItemContainer",0x1288eaf10ULL},{"HackableLockedCrate",0x1289983a0ULL},
             {"SupplyDrop",0x1288499b0ULL},{"BaseCorpse",0x1286106e0ULL},{"StashContainer",0x1297f1740ULL}};
    const int NC=11;
    for(int i=0;i<NC;i++){ char nm[128]={0}; uint64_t p=r64(C[i].k+0x10); if(rd(p,nm,120)) nm[120]=0;
        printf("%-22s 0x%-11llx %s%s\n",C[i].n,(unsigned long long)C[i].k,nm,strcmp(nm,C[i].n)?"  <<< INCOHERENT":""); }
    uint64_t KM=C[2].k, KP=C[0].k, KPM=C[1].k;
    // balayage : instances de toutes les classes
    const size_t CH=8u<<20; std::vector<unsigned char> buf(CH);
    std::vector<std::vector<uint64_t>> hits(NC);
    for(auto&r:R) for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+8<=(size_t)g;i+=8){ uint64_t v=*(uint64_t*)(buf.data()+i);
            for(int k=0;k<NC;k++) if(v==C[k].k){ hits[k].push_back(c+i); break; } } }
    printf("\nrefs : "); for(int k=0;k<NC;k++) printf("%s=%zu ",C[k].n,hits[k].size()); printf("\n");
    // joueurs : vérité terrain vs chaîne
    printf("\n=== JOUEURS : PM+0x2F8 (verite) vs chaine ===\n");
    int nok=0,nko=0,nbp=0;
    float sx=0,sy=0,sz2=0;
    for(uint64_t a:hits[0]){ if(nbp>=8) break; if(r64(a)!=KP) continue;
        uint64_t m=r64(a+0x1B8); if(m<0x1000000||r64(m)!=KM) continue;
        uint64_t p=r64(a+0x328); if(p<0x1000000||r64(p)!=KPM) continue;
        float v[3]; if(!rd(p+0x2F8,v,12)) continue; if(!sane(v)) continue;
        float c2[3]={0,0,0}; bool ok=chain_pos(a,c2);
        float dx=c2[0]-v[0],dy=c2[1]-v[1],dz=c2[2]-v[2];
        float e=sqrtf(dx*dx+dy*dy+dz*dz);
        printf("  bp=0x%llx verite=(%9.2f %7.2f %9.2f) chaine=%s (%9.2f %7.2f %9.2f) ecart=%.3f m\n",
            (unsigned long long)a,v[0],v[1],v[2], ok?"OK ":"ECHEC",c2[0],c2[1],c2[2], ok?e:-1.0f);
        if(ok){ if(e<0.5f){ok?nok++:nko++;} else nko++; } nbp++; }
    printf("  -> %d ecarts<0.5m / %d joueurs testes\n",nok,nbp);
    // entités : positions via la chaîne
    for(int k=3;k<NC;k++){
        int n=0,valid=0; printf("\n=== %s ===\n",C[k].n);
        for(uint64_t a:hits[k]){ if(r64(a)!=C[k].k) continue;
            uint64_t m=r64(a+0x1B8); if(m<0x1000000||r64(m)!=KM) continue; n++;
            if(n>8) break;
            float p[3]={0,0,0}; bool ok=chain_pos(a,p);
            printf("  obj=0x%llx model=0x%llx %s",(unsigned long long)a,(unsigned long long)m,ok?"pos=":"chaine KO ");
            if(ok){ printf("(%9.2f %7.2f %9.2f)",p[0],p[1],p[2]); valid++; }
            printf("\n"); }
        printf("  -> %d entites (modele valide), %d positions\n",n,valid);
    }
    printf("\ntotal %.1f s\n",(double)clock()/CLOCKS_PER_SEC-t0);
    return 0;
}
