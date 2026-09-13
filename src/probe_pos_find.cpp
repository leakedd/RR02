// probe_pos_find — où vit la position monde ?
// 1) klasses par nom  2) joueur réel + position connue (PlayerModel+0x2F8)
// 3) balayage de la mémoire à la recherche du triplet de floats == position connue
// 4) pour chaque hit : qui pointe dessus (2e balayage) -> chaîne d'accès
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
#include <unordered_set>
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
static const char* WANT[]={"BasePlayer","PlayerModel","Model","PlayerCorpse","DroppedItem","DroppedItemContainer"};
static const int NW=6;
int main(){
    setvbuf(stdout,NULL,_IONBF,0);
    double t0=(double)clock()/CLOCKS_PER_SEC;
    pid_t PID=0; { FILE* f=popen("pgrep -x Rust | head -1","r"); char b[64]; if(f&&fgets(b,64,f)) PID=atoi(b); if(f)pclose(f); }
    if(!PID||task_for_pid(mach_task_self(),PID,&T)!=KERN_SUCCESS){ printf("task_for_pid KO\n"); return 1; }
    regions(); printf("regions=%zu (%.1f Go)\n",R.size(),[&]{double s=0;for(auto&r:R)s+=r.sz;return s/1073741824.0;}());
    uint64_t K[NW]={0}; const size_t CH=8u<<20; std::vector<unsigned char> buf(CH);
    // ---- passe A : klasses ----
    for(auto&r:R){ for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+0x88<=(size_t)g;i+=8){ uint64_t X=c+i;
            if(*(uint64_t*)(buf.data()+i+0x78)!=X) continue;
            char nm[128]; uint64_t p=*(uint64_t*)(buf.data()+i+0x10); if(!p||!str_at(p,nm,sizeof(nm))) continue;
            for(int k=0;k<NW;k++) if(!K[k]&&!strcmp(nm,WANT[k])) K[k]=X; } } }
    printf("passe A %.1f s :",(double)clock()/CLOCKS_PER_SEC-t0); for(int k=0;k<NW;k++) printf(" %s=0x%llx",WANT[k],(unsigned long long)K[k]); printf("\n");
    // ---- passe B : un joueur réel + sa position ----
    std::vector<uint64_t> bpRefs; double tb=(double)clock()/CLOCKS_PER_SEC;
    for(auto&r:R){ for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+8<=(size_t)g;i+=8) if(*(uint64_t*)(buf.data()+i)==K[0]) bpRefs.push_back(c+i); } }
    printf("passe B %.1f s : %zu refs BasePlayer\n",(double)clock()/CLOCKS_PER_SEC-tb,bpRefs.size());
    uint64_t bp=0,pm=0,model=0; float pos[3]={0,0,0};
    for(uint64_t a:bpRefs){ if(r64(a)!=K[0]) continue;
        uint64_t m=r64(a+0x1B8); if(m<0x1000000||r64(m)!=K[2]) continue;
        uint64_t p=r64(a+0x328); if(p<0x1000000||r64(p)!=K[1]) continue;
        float v[3]; if(!rd(p+0x2F8,v,12)) continue;
        if(!(std::isfinite(v[0])&&std::isfinite(v[2])&&fabsf(v[0])<6000&&fabsf(v[2])<6000&&fabsf(v[0])+fabsf(v[2])>5)) continue;
        bp=a;pm=p;model=m;memcpy(pos,v,12); break; }
    if(!bp){ printf("aucun joueur valide\n"); return 1; }
    printf("joueur de référence : bp=0x%llx model=0x%llx pm=0x%llx pos=(%.3f %.3f %.3f) model==pm? %s\n",
        (unsigned long long)bp,(unsigned long long)model,(unsigned long long)pm,pos[0],pos[1],pos[2],model==pm?"OUI":"non");
    // ---- passe C : où vit ce triplet ? ----
    std::vector<uint64_t> hits; double tc=(double)clock()/CLOCKS_PER_SEC;
    for(auto&r:R){ for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+12<=(size_t)g;i+=4){ float f[3]; memcpy(f,buf.data()+i,12);
            if(fabsf(f[0]-pos[0])<0.35f&&fabsf(f[1]-pos[1])<0.35f&&fabsf(f[2]-pos[2])<0.35f) hits.push_back(c+i); } } }
    printf("passe C %.1f s : %zu occurrences du triplet\n",(double)clock()/CLOCKS_PER_SEC-tc,hits.size());
    // ---- passe D : qui pointe sur ces adresses ? ----
    std::vector<std::pair<uint64_t,uint64_t>> ptrs; double td=(double)clock()/CLOCKS_PER_SEC;
    if(hits.size()<=64){
        std::unordered_set<uint64_t> hset; std::map<uint64_t,uint64_t> back;
        for(uint64_t h:hits) for(uint64_t d=0; d<=0x40; d+=4){ hset.insert(h+d); back[h+d]=h; }
        for(auto&r:R){ for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
            mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
            for(size_t i=0;i+8<=(size_t)g;i+=8){ uint64_t v=*(uint64_t*)(buf.data()+i);
                if(hset.count(v)) ptrs.push_back({c+i,back[v]}); } } }
    }
    printf("passe D %.1f s : %zu pointeurs vers ces zones\n",(double)clock()/CLOCKS_PER_SEC-td,ptrs.size());
    for(uint64_t h:hits){ printf("\nHIT 0x%llx :\n",(unsigned long long)h);
        float f[8]; if(rd(h-0x20,f,sizeof(f))){ printf("   avant : "); for(int i=0;i<8;i++) printf("%.2f ",f[i]); printf("\n"); }
        uint64_t q[6]; if(rd(h-0x10,q,sizeof(q))){ printf("   qwords avant :"); for(int i=0;i<2;i++) printf(" 0x%llx",(unsigned long long)q[i]); printf("\n"); }
        if(rd(h+0x20,f,sizeof(f))){ printf("   apres : "); for(int i=0;i<8;i++) printf("%.2f ",f[i]); printf("\n"); }
        int n=0; for(auto&p:ptrs){ if(p.second==h|| (p.second<=h&&p.second+0x40>=h)){ if(n++>=6) break;
            uint64_t owner=p.first, back=0; for(int b=0;b<0x120;b+=8){ uint64_t cand=owner-b; uint64_t kv=r64(cand);
                if(kv>0x100000000ULL&&kv<0x140000000ULL&&r64(kv+0x78)==kv){ char nm[128]; uint64_t np=r64(kv+0x10);
                    if(np&&str_at(np,nm,sizeof(nm))){ back=b; printf("   pointeur 0x%llx (objet a -0x%llx, klass \"%s\")\n",(unsigned long long)owner,(unsigned long long)back,nm); break; } } } } }
    }
    if(hits.empty()) printf("\n(aucune occurrence : la position n'est pas stockée en clair -> matrix/transform parenté)\n");
    printf("\ntotal %.1f s\n",(double)clock()/CLOCKS_PER_SEC-t0);
    return 0;
}
