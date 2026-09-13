// probe_me — identifier "moi" automatiquement via MainCamera.
// 1) trouve les klasses MainCamera / BasePlayer / PlayerModel par nom (auto-ref du klass)
// 2) lit les champs STATIQUES de MainCamera (static_fields = klass+0xB8)
// 3) tente d'en extraire la position monde de la camera (transform ou Vector3 statiques)
// 4) classe les joueurs par distance a la camera -> le plus proche = moi
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

static task_t T;
static bool rd(uint64_t a,void*b,size_t n){ mach_vm_size_t g=0;
    return mach_vm_read_overwrite(T,a,n,(mach_vm_address_t)b,&g)==KERN_SUCCESS && g==n; }
static uint64_t r64(uint64_t a){ uint64_t v=0; rd(a,&v,8); return v; }
static bool str_at(uint64_t a,char*out,size_t n){ if(!rd(a,out,n-1)) return false; out[n-1]=0; if(!out[0]) return false;
    for(size_t i=0;out[i];i++) if((unsigned char)out[i]<0x20||(unsigned char)out[i]>0x7e) return false; return true; }
static std::string kname(uint64_t o){ if(o<0x1000000) return "-"; uint64_t k=r64(o); if(k<0x1000000) return "?";
    char b[160]={0}; uint64_t np=r64(k+0x10); if(!np||!str_at(np,b,sizeof(b))) return "?"; return std::string(b); }
static bool sane(const float*v){ return std::isfinite(v[0])&&std::isfinite(v[1])&&std::isfinite(v[2])
    && fabsf(v[0])<6000&&fabsf(v[2])<6000&&v[1]>0.2f&&v[1]<900; }
struct Reg{ uint64_t a,sz; }; static std::vector<Reg> R;
static void regions(){ mach_vm_address_t a=0x100000000ULL;
    for(;;){ mach_vm_address_t q=a; mach_vm_size_t sz=0; vm_region_basic_info_data_64_t bi; mach_port_t ob=0;
        mach_msg_type_number_t ci=VM_REGION_BASIC_INFO_COUNT_64;
        if(mach_vm_region(T,&q,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&bi,&ci,&ob)!=KERN_SUCCESS) break;
        if(sz>0&&(bi.protection&VM_PROT_READ)&&(bi.protection&VM_PROT_WRITE)) R.push_back({q,sz});
        if(q+sz<=a) break; a=q+sz; } }
// position monde d'un TransformIL2CPP : +0x10 natif -> +0x28 data -> +0x90 vec3
static bool tpos(uint64_t tr,float*out){ if(tr<0x1000000) return false;
    uint64_t nat=r64(tr+0x10); if(nat<0x1000000) return false;
    uint64_t d=r64(nat+0x28); if(d<0x1000000) return false;
    if(!rd(d+0x90,out,12)) return false; return sane(out); }

int main(){
    setvbuf(stdout,NULL,_IONBF,0);
    pid_t PID=0; { FILE*f=popen("pgrep -x Rust | head -1","r"); char b[64]; if(f&&fgets(b,64,f)) PID=atoi(b); if(f)pclose(f); }
    if(!PID||task_for_pid(mach_task_self(),PID,&T)!=KERN_SUCCESS){ printf("task_for_pid KO\n"); return 1; }
    regions();
    uint64_t kC=0,kB=0,kM=0;
    const size_t CH=8u<<20; std::vector<unsigned char> buf(CH);
    for(auto&r:R) for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+0x88<=(size_t)g;i+=8){ uint64_t X=c+i;
            if(*(uint64_t*)(buf.data()+i+0x78)!=X) continue;
            uint64_t p=*(uint64_t*)(buf.data()+i+0x10); if(!p) continue;
            char nm[128]; if(!str_at(p,nm,sizeof(nm))) continue;
            if(!kC&&!strcmp(nm,"MainCamera")) kC=X;
            else if(!kB&&!strcmp(nm,"BasePlayer")) kB=X;
            else if(!kM&&!strcmp(nm,"PlayerModel")) kM=X; } }
    printf("klasses: MainCamera=0x%llx BasePlayer=0x%llx PlayerModel=0x%llx\n",
        (unsigned long long)kC,(unsigned long long)kB,(unsigned long long)kM);
    if(!kC||!kB||!kM) { printf("klasse manquante\n"); return 1; }

    printf("\n=== MainCamera: statiques ===\n");
    uint64_t sf=r64(kC+0xB8);
    printf("static_fields=0x%llx\n",(unsigned long long)sf);
    for(uint64_t off=0; off<=0x40; off+=8){
        uint64_t v=r64(sf+off); float f[3]={0,0,0}; rd(sf+off,f,12);
        printf("  +0x%02llx = 0x%-11llx %-14s",(unsigned long long)off,(unsigned long long)v,
               (v>=0x1000000?("["+kname(v)+"]").c_str():""));
        if(std::isfinite(f[0])&&std::isfinite(f[2])&&fabsf(f[0])<6000&&fabsf(f[2])<6000&&fabsf(f[0])>0.5f)
            printf("  (float: %.1f %.2f %.1f)",f[0],f[1],f[2]);
        printf("\n"); }

    // candidats transform / camera portes par les statiques
    float cam[3]={0,0,0}; bool haveCam=false; const char* src="aucun";
    for(uint64_t off : {(uint64_t)0x00,(uint64_t)0x08,(uint64_t)0x30,(uint64_t)0x38}){
        uint64_t o=r64(sf+off); if(o<0x1000000) continue;
        float p[3]; if(tpos(o,p)){ printf("  statique +0x%02llx -> position monde (%.1f %.2f %.1f) via chaine transform\n",
            (unsigned long long)off,p[0],p[1],p[2]); if(!haveCam){cam[0]=p[0];cam[1]=p[1];cam[2]=p[2];haveCam=true;src="transform statique";} }
        // Camera Unity -> son transform
        uint64_t tr=r64(o+0x28); if(tr>=0x1000000 && tpos(tr,p)){ printf("  statique +0x%02llx [+0x28] -> position monde (%.1f %.2f %.1f)\n",
            (unsigned long long)off,p[0],p[1],p[2]); if(!haveCam){cam[0]=p[0];cam[1]=p[1];cam[2]=p[2];haveCam=true;src="camera+0x28";} }
    }
    // Vector3 statiques caches (proprietes get/set)
    for(uint64_t off : {(uint64_t)0x18,(uint64_t)0x40}){
        float f[3]; if(rd(sf+off,f,12)&&std::isfinite(f[0])&&std::isfinite(f[1])&&std::isfinite(f[2])
           && fabsf(f[0])<6000&&fabsf(f[2])<6000&&fabsf(f[1])>0.2f&&fabsf(f[1])<900){
            printf("  Vector3 statique +0x%02llx = (%.1f %.2f %.1f)\n",(unsigned long long)off,f[0],f[1],f[2]);
            if(!haveCam){cam[0]=f[0];cam[1]=f[1];cam[2]=f[2];haveCam=true;src="Vector3 statique";} } }
    if(!haveCam){ printf("\n=> position camera NON trouvee\n"); return 2; }
    printf("\n=> camera (source: %s) = (%.1f %.2f %.1f)\n",src,cam[0],cam[1],cam[2]);

    printf("\n=== joueurs tries par distance a la camera ===\n");
    struct Pj{ uint64_t a; float x,y,z; float d; };
    std::vector<Pj> pl;
    for(auto&r:R) for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+8<=(size_t)g;i+=8){ uint64_t v=*(uint64_t*)(buf.data()+i);
            if(v!=kB) continue; uint64_t o=c+i; if(r64(o)!=kB) continue;
            uint64_t m=r64(o+0x328); if(m<0x1000000||r64(m)!=kM) continue;
            float p[3]; if(!rd(m+0x2F8,p,12)||!sane(p)) continue;
            float dx=p[0]-cam[0],dz=p[2]-cam[2];
            pl.push_back({o,p[0],p[1],p[2],sqrtf(dx*dx+dz*dz)}); } }
    std::sort(pl.begin(),pl.end(),[](const Pj&a,const Pj&b){return a.d<b.d;});
    printf("total joueurs=%zu\n",pl.size());
    for(size_t i=0;i<pl.size()&&i<8;i++)
        printf("  %s d=%7.2f m  (%.1f %.1f %.1f)  obj=0x%llx\n", i==0?"<-- MOI ?":"       ",
               pl[i].d,pl[i].x,pl[i].y,pl[i].z,(unsigned long long)pl[i].a);
    return 0;
}
