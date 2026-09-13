// probe_idx — table de transforms (pas de 32 o : pos|quat|scalaire) : trouver la BASE
// et l'INDEX pour remonter d'une entité à sa position.
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
int main(){
    setvbuf(stdout,NULL,_IONBF,0);
    double t0=(double)clock()/CLOCKS_PER_SEC;
    pid_t PID=0; { FILE* f=popen("pgrep -x Rust | head -1","r"); char b[64]; if(f&&fgets(b,64,f)) PID=atoi(b); if(f)pclose(f); }
    if(!PID||task_for_pid(mach_task_self(),PID,&T)!=KERN_SUCCESS){ printf("task_for_pid KO\n"); return 1; }
    regions();
    const char* WANT[]={"BasePlayer","PlayerModel","Model"};
    const int NW=3; uint64_t K[NW]={0};
    const size_t CH=8u<<20; std::vector<unsigned char> buf(CH);
    for(auto&r:R){ for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+0x88<=(size_t)g;i+=8){ uint64_t X=c+i;
            if(*(uint64_t*)(buf.data()+i+0x78)!=X) continue;
            char nm[128]; uint64_t p=*(uint64_t*)(buf.data()+i+0x10); if(!p||!str_at(p,nm,sizeof(nm))) continue;
            for(int k=0;k<NW;k++) if(!K[k]&&!strcmp(nm,WANT[k])) K[k]=X; } } }
    printf("passe A %.1f s : BP=0x%llx PM=0x%llx Model=0x%llx\n",(double)clock()/CLOCKS_PER_SEC-t0,
        (unsigned long long)K[0],(unsigned long long)K[1],(unsigned long long)K[2]);
    // passe B : un joueur valide
    uint64_t bp=0,pm=0,model=0; float pos[3]={0,0,0};
    std::vector<uint64_t> refs;
    for(auto&r:R){ for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+8<=(size_t)g;i+=8) if(*(uint64_t*)(buf.data()+i)==K[0]) refs.push_back(c+i); } }
    printf("passe B %.1f s : %zu refs BP\n",(double)clock()/CLOCKS_PER_SEC-t0,refs.size());
    for(uint64_t a:refs){ if(r64(a)!=K[0]) continue;
        uint64_t m=r64(a+0x1B8); if(m<0x1000000||r64(m)!=K[2]) continue;
        uint64_t p=r64(a+0x328); if(p<0x1000000||r64(p)!=K[1]) continue;
        float v[3]; if(!rd(p+0x2F8,v,12)) continue;
        if(!(std::isfinite(v[0])&&std::isfinite(v[1])&&fabsf(v[0])<6000&&fabsf(v[2])<6000&&v[1]>0.5f&&v[1]<900)) continue;
        bp=a;pm=p;model=m;memcpy(pos,v,12); break; }
    if(!bp){ printf("pas de joueur\n"); return 1; }
    printf("joueur bp=0x%llx model=0x%llx pm=0x%llx pos=(%.2f %.2f %.2f) model==pm? %s\n",
        (unsigned long long)bp,(unsigned long long)model,(unsigned long long)pm,pos[0],pos[1],pos[2],model==pm?"OUI":"non");
    // passe C : occurrences + sélection des enregistrements "pos|quat|scalaire"
    std::vector<uint64_t> hits; std::vector<uint64_t> rec;
    for(auto&r:R){ for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+12<=(size_t)g;i+=4){ float f[3]; memcpy(f,buf.data()+i,12);
            if(fabsf(f[0]-pos[0])<0.35f&&fabsf(f[1]-pos[1])<0.35f&&fabsf(f[2]-pos[2])<0.35f){
                uint64_t h=c+i; hits.push_back(h);
                float q[4]; if(rd(h+12,q,16)){ float n=sqrtf(q[0]*q[0]+q[1]*q[1]+q[2]*q[2]+q[3]*q[3]);
                    if(fabsf(n-1.0f)<0.05f) rec.push_back(h); } } } } }
    printf("passe C %.1f s : %zu occurrences, %zu enregistrements pos|quat\n",(double)clock()/CLOCKS_PER_SEC-t0,hits.size(),rec.size());
    for(uint64_t h:rec) printf("   REC 0x%llx (mod32=%llu)\n",(unsigned long long)h,(unsigned long long)(h%32));
    if(rec.empty()) return 1;
    uint64_t rc=rec[0];
    // --- chaîne : model+0x28 -> Transform IL2CPP -> pointeurs natifs ---
    uint64_t tr=r64(model+0x28);
    printf("\nModel+0x28 (rootBone) = 0x%llx klass=0x%llx\n",(unsigned long long)tr,(unsigned long long)r64(tr));
    uint64_t q[16]; if(!rd(tr,q,sizeof(q))){ printf("Transform illisible\n"); return 1; }
    printf("Transform IL2CPP (16 qwords) :\n"); for(int i=0;i<16;i++) printf("   +0x%02x 0x%llx (%lld)\n",i*8,(unsigned long long)q[i],(long long)q[i]);
    for(int i=0;i<16;i++){ uint64_t p=q[i]; if(p<0x1000000||p>0x300000000000ULL) continue;
        uint64_t w[32]; if(!rd(p,w,sizeof(w))) continue;
        printf("\n  -> natif +0x%02x = 0x%llx : 32 qwords\n",i*8,(unsigned long long)p);
        for(int k=0;k<32;k++){
            long long delta=(long long)(rc-w[k]);
            bool isbase = (w[k]<=rc) && delta>=0 && delta<0x4000000 && (delta%32==0);
            printf("     +0x%03x 0x%016llx %s",k*8,(unsigned long long)w[k], isbase?"<<< BASE+INDEX POSSIBLE":"");
            if(isbase) printf("  index=%lld (delta=%lld)",delta/32,delta);
            printf("\n"); }
        // ints (index souvent en 32 bits)
        printf("     ints: "); for(int k=0;k<16;k++){ uint32_t iv=0; rd(p+k*4,&iv,4); printf("%u ",iv); } printf("\n");
    }
    // --- chaîne depuis l'entité elle-même (TransformHandle) ---
    uint64_t h90=r64(bp+0x90);
    printf("\nbp+0x90 (TransformHandle.pTransformData) = 0x%llx\n",(unsigned long long)h90);
    if(h90>0x1000000){ uint64_t w[16]; if(rd(h90,w,sizeof(w))){
        printf("   contenu :\n"); for(int k=0;k<16;k++){ long long d=(long long)(rc-w[k]);
            printf("     +0x%02x 0x%016llx %s\n",k*8,(unsigned long long)w[k], (w[k]<=rc&&d>=0&&d<0x4000000&&d%32==0)?("<<< BASE index="+std::to_string(d/32)).c_str():""); } } }
    printf("\ntotal %.1f s\n",(double)clock()/CLOCKS_PER_SEC-t0);
    return 0;
}
