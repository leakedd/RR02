// probe_chain — toutes les hypothèses de position en une seule exécution.
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
static bool str_at(uint64_t a,char*out,size_t n){ if(!rd(a,out,n-1)) return false; out[n-1]=0; if(!out[0]) return false;
    for(size_t i=0;out[i];i++) if((unsigned char)out[i]<0x20||(unsigned char)out[i]>0x7e) return false; return true; }
struct Reg{ uint64_t a,sz; }; static std::vector<Reg> R;
static void regions(){ mach_vm_address_t a=0x100000000ULL;
    for(;;){ mach_vm_address_t q=a; mach_vm_size_t sz=0; vm_region_basic_info_data_64_t bi; mach_port_t ob=0;
        mach_msg_type_number_t ci=VM_REGION_BASIC_INFO_COUNT_64;
        if(mach_vm_region(T,&q,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&bi,&ci,&ob)!=KERN_SUCCESS) break;
        if(sz>0&&(bi.protection&VM_PROT_READ)&&(bi.protection&VM_PROT_WRITE)) R.push_back({q,sz});
        if(q+sz<=a) break; a=q+sz; } }
static bool sane(const float*v){ return std::isfinite(v[0])&&std::isfinite(v[1])&&std::isfinite(v[2])
    && fabsf(v[0])<6000&&fabsf(v[2])<6000&&v[1]>0.5f&&v[1]<900; }
int main(){
    setvbuf(stdout,NULL,_IONBF,0);
    double t0=(double)clock()/CLOCKS_PER_SEC;
    pid_t PID=0; { FILE* f=popen("pgrep -x Rust | head -1","r"); char b[64]; if(f&&fgets(b,64,f)) PID=atoi(b); if(f)pclose(f); }
    if(!PID||task_for_pid(mach_task_self(),PID,&T)!=KERN_SUCCESS){ printf("task_for_pid KO\n"); return 1; }
    regions();
    const char* WANT[]={"BasePlayer","PlayerModel","Model","Transform"}; const int NW=4; uint64_t K[NW]={0};
    const size_t CH=8u<<20; std::vector<unsigned char> buf(CH);
    for(auto&r:R) for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+0x88<=(size_t)g;i+=8){ uint64_t X=c+i;
            if(*(uint64_t*)(buf.data()+i+0x78)!=X) continue;
            char nm[128]; uint64_t p=*(uint64_t*)(buf.data()+i+0x10); if(!p||!str_at(p,nm,sizeof(nm))) continue;
            for(int k=0;k<NW;k++) if(!K[k]&&!strcmp(nm,WANT[k])) K[k]=X; } }
    printf("passe A %.1f s : BP=0x%llx PM=0x%llx Model=0x%llx Transform=0x%llx\n",(double)clock()/CLOCKS_PER_SEC-t0,
        (unsigned long long)K[0],(unsigned long long)K[1],(unsigned long long)K[2],(unsigned long long)K[3]);
    std::vector<uint64_t> refs;
    for(auto&r:R) for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+8<=(size_t)g;i+=8) if(*(uint64_t*)(buf.data()+i)==K[0]) refs.push_back(c+i); }
    printf("passe B %.1f s : %zu refs\n",(double)clock()/CLOCKS_PER_SEC-t0,refs.size());
    uint64_t bp=0,model=0,pm=0; float pos[3];
    for(uint64_t a:refs){ if(r64(a)!=K[0]) continue;
        uint64_t m=r64(a+0x1B8); if(m<0x1000000||r64(m)!=K[2]) continue;
        uint64_t p=r64(a+0x328); if(p<0x1000000||r64(p)!=K[1]) continue;
        float v[3]; if(!rd(p+0x2F8,v,12)) continue; if(!sane(v)) continue;
        bp=a;model=m;pm=p;memcpy(pos,v,12); break; }
    printf("joueur bp=0x%llx model=0x%llx pm=0x%llx pos=(%.2f %.2f %.2f)\n",
        (unsigned long long)bp,(unsigned long long)model,(unsigned long long)pm,pos[0],pos[1],pos[2]);
    // Transform IL2CPP : klass -> nom, + natif
    uint64_t tr=r64(model+0x28);
    char tn[128]={"?"}; uint64_t tk=r64(tr); if(tk) str_at(r64(tk+0x10),tn,sizeof(tn));
    uint64_t nat=r64(tr+0x10);
    printf("model+0x28 -> 0x%llx klass=0x%llx (%s)  natif(m_CachedPtr +0x10)=0x%llx\n",
        (unsigned long long)tr,(unsigned long long)tk,tn,(unsigned long long)nat);
    // REC : positions en clair
    std::vector<uint64_t> rec;
    { std::vector<unsigned char> rbuf(0x400);
      for(auto&r:R) for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+28<=(size_t)g;i+=4){ float f[3]; memcpy(f,buf.data()+i,12);
            if(fabsf(f[0]-pos[0])<0.3f&&fabsf(f[1]-pos[1])<0.3f&&fabsf(f[2]-pos[2])<0.3f){
                uint64_t h=c+i; float q[4]; if(rd(h+12,q,16)){ float n2=sqrtf(q[0]*q[0]+q[1]*q[1]+q[2]*q[2]+q[3]*q[3]);
                    if(fabsf(n2-1.0f)<0.05f) rec.push_back(h); } } } } }
    printf("REC (pos|quat unitaire) : %zu\n",rec.size());
    for(uint64_t h:rec) printf("   0x%llx\n",(unsigned long long)h);
    if(rec.empty()){ printf("pas de REC\n"); return 1; }
    uint64_t r0=rec[0];
    // H1 : table indexée depuis pTransformData et son voisinage
    uint64_t cands[64]; int nc=0;
    uint64_t h90=r64(bp+0x90);
    for(int off=0; off<0x80 && nc<64; off+=8){ uint64_t v=r64(h90+off); if(v>0x1000000&&v<0x300000000000ULL) cands[nc++]=v; }
    for(int off=0; off<0x100 && nc<64; off+=8){ uint64_t v=r64(nat+off); if(v>0x1000000&&v<0x300000000000ULL) cands[nc++]=v; }
    printf("\n=== H1/H2 : tableaux candidats (32 o de pas) ===\n");
    for(int ci=0;ci<nc;ci++){ uint64_t base=cands[ci];
        if((r0>=base)&&((r0-base)%32==0)&&(r0-base)<0x4000000)
            printf("  BASE 0x%llx  index(r0)=%llu\n",(unsigned long long)base,(unsigned long long)((r0-base)/32));
        unsigned char tb[0x4000]; if(!rd(base,tb,sizeof(tb))) continue;
        for(size_t i=0;i+12<=sizeof(tb);i+=4){ float f[3]; memcpy(f,tb+i,12);
            if(fabsf(f[0]-pos[0])<0.3f&&fabsf(f[1]-pos[1])<0.3f&&fabsf(f[2]-pos[2])<0.3f)
                printf("  CONTIENT la pos : base 0x%llx + 0x%zx\n",(unsigned long long)base,i); }
    }
    // H3 : 2 niveaux depuis le natif
    printf("\n=== H3 : pointeurs imbriqués du Transform natif ===\n");
    uint64_t nq[32]; if(rd(nat,nq,sizeof(nq))){
        for(int i=2;i<32;i++){ uint64_t p=nq[i]; if(p<0x1000000||p>0x300000000000ULL) continue;
            unsigned char tb[0x4000]; if(!rd(p,tb,sizeof(tb))) continue;
            for(size_t k=0;k+12<=sizeof(tb);k+=4){ float f[3]; memcpy(f,tb+k,12);
                if(fabsf(f[0]-pos[0])<0.3f&&fabsf(f[1]-pos[1])<0.3f&&fabsf(f[2]-pos[2])<0.3f)
                    printf("  nat[+0x%02x]=0x%llx -> pos à +0x%zx\n",i*8,(unsigned long long)p,k); } } }
    // H4 : qui pointe DANS le tableau (balayage)
    printf("\n=== H4 : balayage — pointeurs vers la table ===\n");
    int found=0;
    for(auto&r:R) for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+8<=(size_t)g;i+=8){ uint64_t w=*(uint64_t*)(buf.data()+i);
            if(w<0x1000000||w>r0||r0-w>0x200000) continue;
            if((r0-w)%32) continue;
            printf("  POINTEUR 0x%llx (à 0x%llx) -> delta=%llu index=%llu\n",(unsigned long long)w,
                (unsigned long long)(c+i),(unsigned long long)(r0-w),(unsigned long long)((r0-w)/32));
            if(++found>40) goto fin; } }
fin:
    printf("total %.1f s\n",(double)clock()/CLOCKS_PER_SEC-t0);
    return 0;
}
