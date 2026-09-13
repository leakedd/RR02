// probe_item2 — (A) calibre le layout natif du Transform sur un JOUEUR connu
//                (B) dump les instances DroppedItem : position + chaine des noms
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
static uint64_t find_klass(const char* want){
    const size_t CH=8u<<20; std::vector<unsigned char> buf(CH); uint64_t f=0;
    for(auto&r:R){ for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+0x88<=(size_t)g;i+=8){ uint64_t X=c+i;
            if(*(uint64_t*)(buf.data()+i+0x78)!=X) continue;
            char nm[128]; uint64_t p=*(uint64_t*)(buf.data()+i+0x10); if(!p||!str_at(p,nm,sizeof(nm))) continue;
            if(!strcmp(nm,want)){ f=X; goto done; } } } }
 done: return f;
}
static std::vector<uint64_t> find_refs(uint64_t val){
    const size_t CH=8u<<20; std::vector<unsigned char> buf(CH); std::vector<uint64_t> out;
    for(auto&r:R){ for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+8<=(size_t)g;i+=8) if(*(uint64_t*)(buf.data()+i)==val) out.push_back(c+i); } }
    return out;
}
static void dump_strings(uint64_t base,uint64_t lo,uint64_t hi,std::map<std::string,uint64_t>&seen,const char*tag){
    for(uint64_t off=lo; off<=hi; off+=8){ uint64_t p=r64(base+off); char s[200];
        if(p&&mstr(p,s,sizeof(s))&&!seen.count(s)){ seen[s]=base+off; printf("      %s[+0x%02llx] \"%s\"\n",tag,(unsigned long long)off,s); } }
}
int main(){
    pid_t PID=0; { FILE* f=popen("pgrep -x Rust | head -1","r"); char b[64]; if(f&&fgets(b,64,f)) PID=atoi(b); if(f)pclose(f); }
    if(!PID||task_for_pid(mach_task_self(),PID,&T)!=KERN_SUCCESS){ printf("task_for_pid KO (root requis)\n"); return 1; }
    regions();
    uint64_t kpm=find_klass("PlayerModel"), kb=find_klass("BasePlayer"), kd=find_klass("DroppedItem"), km=find_klass("Model");
    printf("klass PM=0x%llx BP=0x%llx DroppedItem=0x%llx Model=0x%llx | regions=%zu\n",
        (unsigned long long)kpm,(unsigned long long)kb,(unsigned long long)kd,(unsigned long long)km,R.size());
    if(!kpm||!kb) return 1;

    // ---------- (A) CALIBRATION sur joueur ----------
    std::vector<uint64_t> pms=find_refs(kpm);
    printf("\n[A] candidats PlayerModel (valeur==klass): %zu\n",pms.size());
    int cal=0;
    for(uint64_t pm : pms){
        float pos[3]; if(!rd(pm+0x2F8,pos,12)) continue;
        if(!(fabsf(pos[0])<5000&&fabsf(pos[2])<5000&&pos[1]>-50&&pos[1]<500)) continue;
        // BasePlayer dont +0x328 == pm
        uint64_t bp=0; for(uint64_t r : find_refs(pm)){ uint64_t cand=r-0x328; if(cand>0x1000000&&r64(cand)==kb){ bp=cand; break; } }
        if(!bp) continue;
        uint64_t model=r64(bp+0x1B8); if(!r64(model+0x0)||(km&&r64(model)!=km)) model=0;
        printf("  joueur pm=0x%llx pos=(%.2f %.2f %.2f) model=0x%llx\n",(unsigned long long)pm,pos[0],pos[1],pos[2],(unsigned long long)model);
        uint64_t tr[4]={0,0,0,0};
        if(model){ uint64_t root=r64(model+0x28); tr[0]=root;
            for(int k=0;k<3;k++) tr[k+1]=r64(root+0x10+8*k);
        }
        for(int k=0;k<4;k++){ if(!tr[k]) continue;
            float f[64]; if(!rd(tr[k],f,sizeof(f))) continue;
            printf("    natif(0x%llx) : recherche %.2f %.2f %.2f\n",(unsigned long long)tr[k],pos[0],pos[1],pos[2]);
            int hits=0;
            for(int i=0;i<61;i++){ if(fabsf(f[i]-pos[0])<0.6f&&fabsf(f[i+1]-pos[1])<0.6f&&fabsf(f[i+2]-pos[2])<0.6f){
                printf("      >>> MATCH offset +0x%02x : %.2f %.2f %.2f\n",i*4,f[i],f[i+1],f[i+2]); hits++; } }
            if(!hits){ printf("      (pas de match) floats: ");
                for(int i=0;i<24;i++) printf("%.1f ",f[i]); printf("\n"); }
        }
        if(++cal>=2) break;
    }
    if(!cal) printf("  (aucune calibration possible : model/rootBone introuvable)\n");

    // ---------- (B) ITEMS AU SOL ----------
    if(!kd){ printf("\n[B] DroppedItem klass introuvable\n"); return 0; }
    std::vector<uint64_t> cs=find_refs(kd);
    printf("\n[B] candidats DroppedItem: %zu\n",cs.size());
    int shown=0;
    for(uint64_t o : cs){
        uint64_t model=r64(o+0x1B8); uint32_t pref=r32(o+0x54); uint32_t flags=r32(o+0x1C4);
        bool model_ok = model && (!km || r64(model)==km);
        if(!model_ok) continue;
        uint64_t root=r64(model+0x28), item=r64(o+0x208);
        float v118[3]={0},bc[3]={0},be[3]={0};
        rd(o+0x118,v118,12); rd(o+0x18C,bc,12); rd(o+0x198,be,12);
        float tf[2]={0};
        if(!rd(root+0x10,&tf,8)){}
        printf("\n  === 0x%llx prefabID=%u flags=0x%x model=0x%llx root=0x%llx item=0x%llx\n",
            (unsigned long long)o,pref,flags,(unsigned long long)model,(unsigned long long)root,(unsigned long long)item);
        printf("      v@0x118=%.2f %.2f %.2f | bounds.c=%.2f %.2f %.2f | ext=%.2f %.2f %.2f\n",
            v118[0],v118[1],v118[2],bc[0],bc[1],bc[2],be[0],be[1],be[2]);
        if(root){ uint64_t nat=r64(root+0x10), nat2=r64(root+0x18);
            printf("      root+0x10=0x%llx root+0x18=0x%llx\n",(unsigned long long)nat,(unsigned long long)nat2);
            for(uint64_t np : {nat,nat2}){ if(np<0x1000000) continue;
                float f[40]; if(!rd(np,f,sizeof(f))) continue;
                printf("      natif 0x%llx (40 floats, 2 par ligne) :\n",(unsigned long long)np);
                for(int i=0;i<40;i+=2){ printf("       +0x%02x %.2f %.2f\n",i*4,f[i],f[i+1]); } }
        }
        std::map<std::string,uint64_t> seen;
        if(item){ printf("      -- chaine item 0x%llx --\n",(unsigned long long)item);
            dump_strings(item,0x10,0x100,seen,"");
            for(uint64_t off=0x10; off<=0x60; off+=8){ uint64_t q=r64(item+off); if(q>0x1000000&&r64(q)>0x1000000) dump_strings(q,0x10,0x80,seen,"  2> "); }
        }
        if(++shown>=4) break;
    }
    printf("\n[B] instances montrées: %d\n",shown);
    return 0;
}
