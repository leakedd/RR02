// probe_tr — trouve OÙ vit la position monde (Unity Transform natif), en triangulant
// sur un joueur dont la position est connue (PlayerModel+0x2F8).
// Chaîne : BasePlayer+0x1B8 -> Model ; Model+0x28 -> rootBone (Transform IL2CPP) ->
//          pointeurs natifs -> on cherche le triplet de floats == position connue.
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cmath>
#include <vector>
#include <map>
#include <string>
#include <algorithm>
#include <ctime>

static task_t T;
static bool rd(uint64_t a,void*b,size_t n){ mach_vm_size_t g=0;
    return mach_vm_read_overwrite(T,a,n,(mach_vm_address_t)b,&g)==KERN_SUCCESS && g==n; }
static uint64_t r64(uint64_t a){ uint64_t v=0; rd(a,&v,8); return v; }
static uint32_t r32(uint64_t a){ uint32_t v=0; rd(a,&v,4); return v; }
static bool str_at(uint64_t a,char*out,size_t n){ if(!rd(a,out,n-1)) return false; out[n-1]=0; if(!out[0]) return false;
    for(size_t i=0;out[i];i++) if((unsigned char)out[i]<0x20||(unsigned char)out[i]>0x7e) return false; return true; }
struct Reg{ uint64_t a,sz; };
static std::vector<Reg> R;
static void regions(){ mach_vm_address_t a=0x100000000ULL;
    for(;;){ mach_vm_address_t q=a; mach_vm_size_t sz=0; vm_region_basic_info_data_64_t bi; mach_port_t ob=0;
        mach_msg_type_number_t ci=VM_REGION_BASIC_INFO_COUNT_64;
        if(mach_vm_region(T,&q,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&bi,&ci,&ob)!=KERN_SUCCESS) break;
        if(sz>0&&(bi.protection&VM_PROT_READ)&&(bi.protection&VM_PROT_WRITE)) R.push_back({q,sz});
        if(q+sz<=a) break; a=q+sz; } }
static bool near3(const float*f,float x,float y,float z,float tol){
    return fabsf(f[0]-x)<tol&&fabsf(f[1]-y)<tol&&fabsf(f[2]-z)<tol; }
static void hunt(uint64_t base,uint64_t span,const char*label,float x,float y,float z){
    std::vector<unsigned char> b(span);
    if(!rd(base,b.data(),span)){ printf("      %s 0x%llx illisible\n",label,(unsigned long long)base); return; }
    int hits=0;
    for(uint64_t off=0; off+12<=span; off+=4){ float f[3];
        memcpy(f,b.data()+off,12); if(near3(f,x,y,z,0.6f)){ printf("      MATCH dans %s : +0x%03llx = %.3f %.3f %.3f\n",label,(unsigned long long)off,f[0],f[1],f[2]); hits++; } }
    if(!hits){ printf("      pas de match dans %s (0x%llx+%llu)\n",label,(unsigned long long)base,(unsigned long long)span); }
}
int main(){
    setvbuf(stdout,NULL,_IONBF,0);
    double t0=(double)clock()/CLOCKS_PER_SEC;
    pid_t PID=0; { FILE* f=popen("pgrep -x Rust | head -1","r"); char b[64]; if(f&&fgets(b,64,f)) PID=atoi(b); if(f)pclose(f); }
    if(!PID||task_for_pid(mach_task_self(),PID,&T)!=KERN_SUCCESS){ printf("task_for_pid KO\n"); return 1; }
    regions();
    const char* WANT[]={"BasePlayer","PlayerModel","Model","PlayerCorpse"};
    const int NW=4; uint64_t K[NW]={0};
    const size_t CH=8u<<20; std::vector<unsigned char> buf(CH);
    for(auto&r:R){ for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+0x88<=(size_t)g;i+=8){ uint64_t X=c+i;
            if(*(uint64_t*)(buf.data()+i+0x78)!=X) continue;
            char nm[128]; uint64_t p=*(uint64_t*)(buf.data()+i+0x10); if(!p||!str_at(p,nm,sizeof(nm))) continue;
            for(int k=0;k<NW;k++) if(!K[k]&&!strcmp(nm,WANT[k])) K[k]=X; } } }
    for(int k=0;k<NW;k++) printf("klass %-12s = 0x%llx\n",WANT[k],(unsigned long long)K[k]);
    std::vector<uint64_t> *hit=new std::vector<uint64_t>[NW];
    for(auto&r:R){ for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+8<=(size_t)g;i+=8){ uint64_t v=*(uint64_t*)(buf.data()+i);
            for(int k=0;k<NW;k++) if(K[k]&&v==K[k]){ hit[k].push_back(c+i); break; } } } }
    printf("refs BP=%zu PM=%zu Model=%zu PlayerCorpse=%zu (%.1f s)\n",
        hit[0].size(),hit[1].size(),hit[2].size(),hit[3].size(),(double)clock()/CLOCKS_PER_SEC-t0);

    // joueurs réels : BP -> model(+0x1B8) & PM(+0x328)
    struct PJ{ uint64_t bp,model,pm; float pos[3]; };
    std::vector<PJ> PJs;
    for(uint64_t a:hit[0]){ if(r64(a)!=K[0]) continue;
        uint64_t m=r64(a+0x1B8); if(m<0x1000000||r64(m)!=K[2]) continue;
        uint64_t pm=r64(a+0x328); if(pm<0x1000000||r64(pm)!=K[1]) continue;
        float p[3]; if(!rd(pm+0x2F8,p,12)) continue;
        if(!(std::isfinite(p[0])&&std::isfinite(p[2])&&fabsf(p[0])<6000&&fabsf(p[2])<6000&&fabsf(p[0])+fabsf(p[2])>1)) continue;
        PJs.push_back({a,m,pm,{p[0],p[1],p[2]}}); }
    printf("joueurs valides (BP+PM+position) : %zu\n",PJs.size());
    for(size_t i=0;i<PJs.size()&&i<6;i++) printf("   bp=0x%llx model=0x%llx pm=0x%llx pos=(%.1f %.1f %.1f) model==pm? %s\n",
        (unsigned long long)PJs[i].bp,(unsigned long long)PJs[i].model,(unsigned long long)PJs[i].pm,
        PJs[i].pos[0],PJs[i].pos[1],PJs[i].pos[2], PJs[i].model==PJs[i].pm?"OUI":"non");
    if(PJs.empty()) return 1;

    // --- chasse au layout Transform sur les 3 premiers joueurs ---
    for(size_t pi=0; pi<PJs.size()&&pi<3; pi++){
        PJ&j=PJs[pi];
        printf("\n=== joueur %zu pos connue (%.2f %.2f %.2f) model=0x%llx\n",pi,j.pos[0],j.pos[1],j.pos[2],(unsigned long long)j.model);
        uint64_t root=r64(j.model+0x28);
        printf("   Model+0x28 (rootBone) = 0x%llx  klass=0x%llx\n",(unsigned long long)root,(unsigned long long)r64(root));
        uint64_t q[24]; if(!rd(root,q,sizeof(q))){ printf("   rootBone illisible\n"); continue; }
        printf("   premiers qwords du Transform IL2CPP :"); for(int i=0;i<8;i++) printf(" 0x%llx",(unsigned long long)q[i]); printf("\n");
        hunt(root,0x100,"Transform(IL2CPP)",j.pos[0],j.pos[1],j.pos[2]);
        // pour chaque pointeur plausible du Transform : chercher la position dedans
        int tried=0;
        for(int i=2;i<24 && tried<12;i++){ uint64_t p=q[i];
            if(p<0x1000000||p>0x300000000000ULL) continue; tried++;
            std::string lb="nat["+std::to_string(i*8)+"]";
            hunt(p,0x400,lb.c_str(),j.pos[0],j.pos[1],j.pos[2]); }
        // le Model lui-meme (souvent le meme objet que PM) : position directe
        hunt(j.model,0x340,"Model",j.pos[0],j.pos[1],j.pos[2]);
        // et un niveau plus bas : root -> enfants
        for(int i=2;i<24;i++){ uint64_t p=q[i]; if(p<0x1000000||p>0x300000000000ULL) continue;
            uint64_t q2[8]; if(!rd(p,q2,sizeof(q2))) continue;
            for(int k=2;k<8;k++){ uint64_t pp=q2[k]; if(pp<0x1000000||pp>0x300000000000ULL) continue;
                { std::string lb2="nat["+std::to_string(i*8)+"]->["+std::to_string(k*8)+"]"; hunt(pp,0x200,lb2.c_str(),j.pos[0],j.pos[1],j.pos[2]); } } }
    }
    // --- validation croisée : PlayerCorpse ---
    printf("\n=== PlayerCorpse (model+0x1B8) ===\n");
    int n=0;
    for(uint64_t a:hit[3]){ if(r64(a)!=K[3]) continue;
        uint64_t m=r64(a+0x1B8); if(m<0x1000000||r64(m)!=K[2]) continue;
        printf("   corpse=0x%llx model=0x%llx root=0x%llx\n",(unsigned long long)a,(unsigned long long)m,(unsigned long long)r64(m+0x28));
        if(++n>=5) break; }
    printf("\ntotal %.1f s\n",(double)clock()/CLOCKS_PER_SEC-t0);
    return 0;
}
