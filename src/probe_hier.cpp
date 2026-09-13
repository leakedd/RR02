// probe_hier — position monde via BaseNetworkable+0x90 (TransformHandle.pTransformData)
// 1) trouve un joueur (position connue via PlayerModel+0x2F8)
// 2) cherche le triplet de floats de cette position dans la mémoire de pTransformData -> offset
// 3) valide sur un 2e joueur, puis applique à PlayerCorpse / LootContainer / DroppedItem
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
#include <unordered_set>
#include <unordered_map>
#include <string>
#include <algorithm>
#include <ctime>

static task_t T;
static bool rd(uint64_t a,void*b,size_t n){ mach_vm_size_t g=0;
    return mach_vm_read_overwrite(T,a,n,(mach_vm_address_t)b,&g)==KERN_SUCCESS && g==n; }
static uint64_t r64(uint64_t a){ uint64_t v=0; rd(a,&v,8); return v; }
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
static bool sane(const float*p){ return std::isfinite(p[0])&&std::isfinite(p[1])&&std::isfinite(p[2])
    && fabsf(p[0])<6000 && fabsf(p[2])<6000 && p[1]>-80 && p[1]<600 && (fabsf(p[0])+fabsf(p[2])>1); }
int main(){
    setvbuf(stdout,NULL,_IONBF,0);
    double t0=(double)clock()/CLOCKS_PER_SEC;
    pid_t PID=0; { FILE* f=popen("pgrep -x Rust | head -1","r"); char b[64]; if(f&&fgets(b,64,f)) PID=atoi(b); if(f)pclose(f); }
    if(!PID||task_for_pid(mach_task_self(),PID,&T)!=KERN_SUCCESS){ printf("task_for_pid KO\n"); return 1; }
    regions();
    const char* WANT[]={"BasePlayer","PlayerModel","Model","PlayerCorpse","LootContainer","DroppedItem","DroppedItemContainer","HackableLockedCrate","SupplyDrop","BaseCorpse","StashContainer"};
    const int NW=11; uint64_t K[NW]={0};
    const size_t CH=8u<<20; std::vector<unsigned char> buf(CH);
    for(auto&r:R){ for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+0x88<=(size_t)g;i+=8){ uint64_t X=c+i;
            if(*(uint64_t*)(buf.data()+i+0x78)!=X) continue;
            char nm[128]; uint64_t p=*(uint64_t*)(buf.data()+i+0x10); if(!p||!str_at(p,nm,sizeof(nm))) continue;
            for(int k=0;k<NW;k++) if(!K[k]&&!strcmp(nm,WANT[k])) K[k]=X; } } }
    printf("passe A %.1f s\n",(double)clock()/CLOCKS_PER_SEC-t0);
    for(int k=0;k<NW;k++) printf("  %-22s 0x%llx\n",WANT[k],(unsigned long long)K[k]);
    std::unordered_map<uint64_t,int> kidx; for(int k=0;k<NW;k++) if(K[k]) kidx[K[k]]=k;
    std::vector<std::vector<uint64_t>> refs(NW);
    double tb=(double)clock()/CLOCKS_PER_SEC;
    for(auto&r:R){ for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+8<=(size_t)g;i+=8){ auto it=kidx.find(*(uint64_t*)(buf.data()+i));
            if(it!=kidx.end()) refs[it->second].push_back(c+i); } } }
    printf("passe B %.1f s\n",(double)clock()/CLOCKS_PER_SEC-tb);

    // joueurs valides
    struct PJ{ uint64_t bp,pm,model; float pos[3]; };
    std::vector<PJ> PJs;
    for(uint64_t a:refs[0]){ if(r64(a)!=K[0]) continue;
        uint64_t m=r64(a+0x1B8); if(m<0x1000000||r64(m)!=K[2]) continue;
        uint64_t p=r64(a+0x328); if(p<0x1000000||r64(p)!=K[1]) continue;
        float v[3]; if(!rd(p+0x2F8,v,12)||!sane(v)) continue;
        PJs.push_back({a,p,m,{v[0],v[1],v[2]}}); }
    printf("joueurs valides: %zu\n",PJs.size());
    if(PJs.empty()) return 1;

    // offset de la position dans la mémoire de pTransformData, calibré sur le joueur 0
    std::map<int,int> offHits;
    for(size_t pi=0; pi<PJs.size() && pi<6; pi++){
        uint64_t h=r64(PJs[pi].bp+0x90);
        printf("\njoueur %zu pos=(%.2f %.2f %.2f) bp=0x%llx pTransformData(+0x90)=0x%llx id(+0x98)=%llu\n",
            pi,PJs[pi].pos[0],PJs[pi].pos[1],PJs[pi].pos[2],(unsigned long long)PJs[pi].bp,
            (unsigned long long)h,(unsigned long long)r64(PJs[pi].bp+0x98));
        if(h<0x1000000){ printf("   handle vide\n"); continue; }
        float f[192]; if(!rd(h,f,sizeof(f))){ printf("   hierarchy illisible\n"); continue; }
        int nb=0;
        for(int i=0;i<189;i++){ if(fabsf(f[i]-PJs[pi].pos[0])<0.5f&&fabsf(f[i+1]-PJs[pi].pos[1])<0.5f&&fabsf(f[i+2]-PJs[pi].pos[2])<0.5f){
            printf("   MATCH +0x%03x = %.2f %.2f %.2f\n",i*4,f[i],f[i+1],f[i+2]); offHits[i*4]++; if(++nb>=4) break; } }
        if(!nb){ printf("   aucun match sur 0x300 octets. 24 premiers floats :\n     ");
            for(int i=0;i<24;i++) printf("%.2f ",f[i]); printf("\n"); }
    }
    printf("\noffsets matchés : "); for(auto&p:offHits) printf("+0x%x(x%d) ",p.first,p.second); printf("\n");

    // applique le meilleur offset aux autres classes d'entités
    int bestOff=-1,bestN=0; for(auto&p:offHits) if(p.second>bestN){bestN=p.second;bestOff=p.first;}
    printf("\n===== positions via offset +0x%x =====\n",bestOff);
    for(int k=3;k<NW;k++){
        int real=0,saneN=0; std::vector<float> samples;
        for(uint64_t a:refs[k]){ if(r64(a)!=K[k]) continue;
            uint64_t m=r64(a+0x1B8); if(m<0x1000000||r64(m)!=K[2]) continue; real++;
            uint64_t h=r64(a+0x90); if(h<0x1000000) continue;
            float p[3]; if(bestOff<0){ if(!rd(h+0x30,p,12)) continue; } else if(!rd(h+bestOff,p,12)) continue;
            if(sane(p)){ saneN++; if(samples.size()<36) samples.insert(samples.end(),{p[0],p[1],p[2]}); } }
        printf("\n%-22s instances=%d",WANT[k],real);
        if(bestOff<0) printf(" (offset inconnu, lecture de +0x30)\n"); else printf(" positions saines=%d\n",saneN);
        for(size_t i=0;i+2<samples.size();i+=3) printf("      (%.1f %.1f %.1f)\n",samples[i],samples[i+1],samples[i+2]);
    }
    printf("\ntotal %.1f s\n",(double)clock()/CLOCKS_PER_SEC-t0);
    return 0;
}
