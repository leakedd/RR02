// probe_item3 — 2 balayages mémoire seulement :
//   passe A : klasses (auto-ref X+0x78==X + nom)
//   passe B : toutes les instances des klasses cherchées, en un seul parcours
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
#include <set>
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
static bool mstr(uint64_t p,char*out,size_t n){
    if(p<0x1000000) return false;
    uint32_t len=r32(p+0x10); if(len<1||len>120) return false;
    char buf[256]; if(!rd(p+0x14,buf,sizeof(buf))) return false;
    size_t k=0; for(;k<len&&k<n-1;k++){ unsigned char c=buf[k]; if(c<0x20||c>0x7e) break; }
    if(k>=len&&k>0){ memcpy(out,buf,k); out[k]=0; return true; }
    uint16_t w[128]; if(!rd(p+0x14,w,sizeof(w))) return false;
    for(size_t i=0;i<len&&i<n-1;i++){ if(w[i]<0x20||w[i]>0x7e) return false; out[i]=(char)w[i]; }
    out[len]=0; return len>0;
}
struct Reg{ uint64_t a,sz; };
static std::vector<Reg> R;
static void regions(){ mach_vm_address_t a=0x100000000ULL;
    for(;;){ mach_vm_address_t q=a; mach_vm_size_t sz=0; vm_region_basic_info_data_64_t bi; mach_port_t ob=0;
        mach_msg_type_number_t ci=VM_REGION_BASIC_INFO_COUNT_64;
        if(mach_vm_region(T,&q,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&bi,&ci,&ob)!=KERN_SUCCESS) break;
        if(sz>0&&(bi.protection&VM_PROT_READ)&&(bi.protection&VM_PROT_WRITE)) R.push_back({q,sz});
        if(q+sz<=a) break; a=q+sz; } }
static void dump_strings(uint64_t base,uint64_t lo,uint64_t hi,std::map<std::string,uint64_t>&seen,const char*tag){
    for(uint64_t off=lo; off<=hi; off+=8){ uint64_t p=r64(base+off); char s[200];
        if(p&&mstr(p,s,sizeof(s))&&!seen.count(s)){ seen[s]=base+off; printf("        %s[+0x%02llx] \"%s\"\n",tag,(unsigned long long)off,s); } }
}
int main(){
    setvbuf(stdout,NULL,_IONBF,0);
    double t0=(double)clock()/CLOCKS_PER_SEC;
    pid_t PID=0; { FILE* f=popen("pgrep -x Rust | head -1","r"); char b[64]; if(f&&fgets(b,64,f)) PID=atoi(b); if(f)pclose(f); }
    if(!PID||task_for_pid(mach_task_self(),PID,&T)!=KERN_SUCCESS){ printf("task_for_pid KO\n"); return 1; }
    regions();
    double tot=0; for(auto&r:R) tot+=(double)r.sz;
    printf("pid=%d regions=%zu (%.1f Go)\n",PID,R.size(),tot/1073741824.0);

    // ---------- passe A : klasses ----------
    const char* WANT[]={"PlayerModel","Model","DroppedItem","DroppedItemContainer","WorldItem","BasePlayer"};
    const int NW=6; uint64_t K[NW]={0,0,0,0,0,0};
    const size_t CH=8u<<20; std::vector<unsigned char> buf(CH);
    for(auto&r:R){ for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+0x88<=(size_t)g;i+=8){ uint64_t X=c+i;
            if(*(uint64_t*)(buf.data()+i+0x78)!=X) continue;
            char nm[128]; uint64_t p=*(uint64_t*)(buf.data()+i+0x10); if(!p||!str_at(p,nm,sizeof(nm))) continue;
            for(int k=0;k<NW;k++) if(!K[k]&&!strcmp(nm,WANT[k])) K[k]=X; } } }
    printf("passe A : %.1f s\n",(double)clock()/CLOCKS_PER_SEC-t0);
    for(int k=0;k<NW;k++) printf("  klass %-22s = 0x%s%llx\n",WANT[k],K[k]?"":"(absent)",(unsigned long long)K[k]);
    if(!K[1]) return 1;                                  // Model indispensable

    // ---------- passe B : instances ----------
    std::vector<uint64_t> *hit = new std::vector<uint64_t>[NW];
    double tb=(double)clock()/CLOCKS_PER_SEC;
    for(auto&r:R){ for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+8<=(size_t)g;i+=8){ uint64_t v=*(uint64_t*)(buf.data()+i);
            for(int k=0;k<NW;k++) if(K[k]&&v==K[k]){ hit[k].push_back(c+i); break; } } } }
    printf("passe B : %.1f s\n",(double)clock()/CLOCKS_PER_SEC-tb);
    for(int k=0;k<NW;k++) printf("  refs %-22s = %zu\n",WANT[k],hit[k].size());

    // objet valide = là où l'octet 0 vaut la klass (en-tête d'objet IL2CPP)
    auto objsof=[&](int k){ std::vector<uint64_t> o; for(uint64_t a:hit[k]) if(r64(a)==K[k]) o.push_back(a); return o; };
    std::vector<uint64_t> PMS=objsof(0), MOD=objsof(1), IT=objsof(2), ITC=objsof(3), WIT=objsof(4), BPS=objsof(5);
    printf("  objets PlayerModel=%zu Model=%zu DroppedItem=%zu DroppedItemContainer=%zu WorldItem=%zu BasePlayer=%zu\n",
        PMS.size(),MOD.size(),IT.size(),ITC.size(),WIT.size(),BPS.size());

    // ---------- A) calibrage du layout natif du Transform sur un joueur ----------
    std::set<uint64_t> pmset(PMS.begin(),PMS.end());
    printf("\n[A] calibrage Transform (joueur connu -> position PlayerModel+0x2F8)\n");
    int cal=0;
    for(uint64_t bp : BPS){
        uint64_t pm=r64(bp+0x328); if(!pmset.count(pm)) continue;
        float pos[3]; if(!rd(pm+0x2F8,pos,12)) continue;
        if(!(fabsf(pos[0])<6000&&fabsf(pos[2])<6000&&pos[1]>-50&&pos[1]<400)) continue;
        uint64_t model=r64(bp+0x1B8); if(r64(model)!=K[1]){ printf("  (bp 0x%llx : model KO)\n",(unsigned long long)bp); continue; }
        uint64_t root=r64(model+0x28);
        printf("  bp=0x%llx pm=0x%llx pos=(%.2f %.2f %.2f) model=0x%llx rootBone=0x%llx\n",
            (unsigned long long)bp,(unsigned long long)pm,pos[0],pos[1],pos[2],(unsigned long long)model,(unsigned long long)root);
        uint64_t cands[3]={root, r64(root+0x10), r64(root+0x18)};
        for(int c=0;c<3;c++){ uint64_t np=cands[c]; if(np<0x1000000) continue;
            float f[96]; if(!rd(np,f,sizeof(f))) continue;
            int found=0;
            for(int i=0;i<93;i++) if(fabsf(f[i]-pos[0])<0.8f&&fabsf(f[i+1]-pos[1])<0.8f&&fabsf(f[i+2]-pos[2])<0.8f){
                printf("    MATCH source=%s 0x%llx -> offset +0x%03x = %.2f %.2f %.2f\n",
                    c==0?"rootBone(IL2CPP)":(c==1?"m_CachedPtr(+0x10)":"+0x18"),(unsigned long long)np,i*4,f[i],f[i+1],f[i+2]); found++; }
            if(!found&&c>0){ printf("    pas de match sur 0x%llx (extrait) : ",(unsigned long long)np);
                for(int i=0;i<12;i++) printf("%.1f ",f[i]); printf("\n"); }
        }
        if(++cal>=2) break;
    }
    if(!cal) printf("  aucune calibration (pas de BP<->PM)\n");

    // ---------- B) items au sol ----------
    printf("\n[B] DroppedItem :%zu objets, DroppedItemContainer : %zu\n",IT.size(),ITC.size());
    int shown=0,valid=0;
    for(uint64_t o : IT){
        uint64_t model=r64(o+0x1B8); uint32_t pref=r32(o+0x54);
        if(r64(model)!=K[1]) continue;
        valid++;
        if(shown>=4) continue;
        uint64_t root=r64(model+0x28), item=r64(o+0x208);
        float v118[3]={0},bc[3]={0};
        rd(o+0x118,v118,12); rd(o+0x18C,bc,12);
        printf("\n  === 0x%llx prefabID=%u model=0x%llx root=0x%llx item=0x%llx\n",
            (unsigned long long)o,pref,(unsigned long long)model,(unsigned long long)root,(unsigned long long)item);
        printf("      v@0x118=%.2f %.2f %.2f | bounds.center=%.2f %.2f %.2f\n",v118[0],v118[1],v118[2],bc[0],bc[1],bc[2]);
        if(root){ uint64_t nat=r64(root+0x10);
            printf("      root+0x10=0x%llx\n",(unsigned long long)nat);
            if(nat>0x1000000){ float f[24]; if(rd(nat,f,sizeof(f))){
                printf("      natif (24 floats) :\n");
                for(int i=0;i<24;i+=2) printf("        +0x%03x %.2f %.2f\n",i*4,f[i],f[i+1]); } } }
        std::map<std::string,uint64_t> seen;
        if(item){ printf("      -- chaine Item 0x%llx --\n",(unsigned long long)item);
            dump_strings(item,0x10,0xF8,seen,"");
            for(uint64_t off=0x10; off<=0x68; off+=8){ uint64_t q=r64(item+off); if(q>0x1000000&&r64(q)>0x1000000){
                char tag[32]; snprintf(tag,sizeof(tag),"  2>+0x%02llx",(unsigned long long)off); dump_strings(q,0x10,0x68,seen,tag); } } }
        shown++;
    }
    printf("\n[DroppedItem] model valide : %d / %zu refs\n",valid,IT.size());
    // échantillon de positions (via le 1er offset qui matche, sinon bounds.center)
    printf("\n[C] 10 positions candidates (bounds.center) :\n");
    int n=0; for(uint64_t o : IT){ uint64_t model=r64(o+0x1B8); if(r64(model)!=K[1]) continue;
        float bc[3]; if(!rd(o+0x18C,bc,12)) continue;
        if(!(fabsf(bc[0])<6000&&fabsf(bc[2])<6000)) continue;
        printf("   prefabID=%-7u pos=(%.1f %.1f %.1f)\n",r32(o+0x54),bc[0],bc[1],bc[2]); if(++n>=10) break; }
    printf("\ntotal %.1f s\n",(double)clock()/CLOCKS_PER_SEC-t0);
    return 0;
}
