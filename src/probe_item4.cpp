// probe_item4 — découverte STATISTIQUE des champs Vector3 par classe.
// Témoin : PlayerModel doit ressortir à +0x2F8 (validé). On cherche l'équivalent pour DroppedItem.
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
static const int WIN=0x360;                     // fenêtre lue par objet (couvre +0x2F8 et +0x34C)
static bool plausible(float*x,float*y,float*z){
    if(!std::isfinite(*x)||!std::isfinite(*y)||!std::isfinite(*z)) return false;
    if(fabsf(*x)>6000||fabsf(*z)>6000) return false;
    if(*y<-60||*y>500) return false;
    if(fabsf(*x)+fabsf(*z)<1.0f) return false;   // exclut l'origine parfaite
    return true;
}
static void scan_fields(const char*name,const std::vector<uint64_t>&objs,int maxn){
    std::map<int,int> cnt; int used=0;
    std::vector<unsigned char> win(WIN);
    for(uint64_t o : objs){ if(used>=maxn) break;
        if(!rd(o,win.data(),WIN)) continue; used++;
        for(int off=0x10;off<=WIN-12;off+=4){
            float x,y,z; memcpy(&x,win.data()+off,4); memcpy(&y,win.data()+off+4,4); memcpy(&z,win.data()+off+8,4);
            if(plausible(&x,&y,&z)) cnt[off]++; } }
    std::vector<std::pair<int,int>> v(cnt.begin(),cnt.end());
    std::sort(v.begin(),v.end(),[](auto&a,auto&b){return a.second>b.second;});
    printf("\n== %s : %d objets lus sur %zu\n",name,used,objs.size());
    int k=0; for(auto&p:v){ if(k++>=10) break;
        printf("   +0x%03x  %5d/%d objets (%.0f%%)%s\n",p.first,p.second,used,100.0*p.second/std::max(1,used),
               p.first==0x2F8?"   <-- TEMOIN PlayerModel attendu":"");
        if(p.second<std::max(3,used/20)) break; }
}
int main(){
    setvbuf(stdout,NULL,_IONBF,0);
    double t0=(double)clock()/CLOCKS_PER_SEC;
    pid_t PID=0; { FILE* f=popen("pgrep -x Rust | head -1","r"); char b[64]; if(f&&fgets(b,64,f)) PID=atoi(b); if(f)pclose(f); }
    if(!PID||task_for_pid(mach_task_self(),PID,&T)!=KERN_SUCCESS){ printf("task_for_pid KO\n"); return 1; }
    regions();
    const char* WANT[]={"PlayerModel","Model","DroppedItem","DroppedItemContainer","WorldItem","BasePlayer","Item"};
    const int NW=7; uint64_t K[NW]={0};
    const size_t CH=8u<<20; std::vector<unsigned char> buf(CH);
    for(auto&r:R){ for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+0x88<=(size_t)g;i+=8){ uint64_t X=c+i;
            if(*(uint64_t*)(buf.data()+i+0x78)!=X) continue;
            char nm[128]; uint64_t p=*(uint64_t*)(buf.data()+i+0x10); if(!p||!str_at(p,nm,sizeof(nm))) continue;
            for(int k=0;k<NW;k++) if(!K[k]&&!strcmp(nm,WANT[k])) K[k]=X; } } }
    for(int k=0;k<NW;k++) printf("klass %-22s = 0x%llx\n",WANT[k],(unsigned long long)K[k]);
    std::vector<uint64_t> *hit=new std::vector<uint64_t>[NW];
    for(auto&r:R){ for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+8<=(size_t)g;i+=8){ uint64_t v=*(uint64_t*)(buf.data()+i);
            for(int k=0;k<NW;k++) if(K[k]&&v==K[k]){ hit[k].push_back(c+i); break; } } } }
    auto objsof=[&](int k){ std::vector<uint64_t> o; for(uint64_t a:hit[k]) if(r64(a)==K[k]) o.push_back(a); return o; };
    std::vector<uint64_t> PMS=objsof(0),IT=objsof(2),ITC=objsof(3),WIT=objsof(4),BPS=objsof(5);
    printf("objets PM=%zu DroppedItem=%zu DroppedItemContainer=%zu WorldItem=%zu BasePlayer=%zu  (%.1f s)\n",
        PMS.size(),IT.size(),ITC.size(),WIT.size(),BPS.size(),(double)clock()/CLOCKS_PER_SEC-t0);

    scan_fields("PlayerModel (TEMOIN)",PMS,400);
    scan_fields("BasePlayer",BPS,400);
    scan_fields("DroppedItem",IT,400);
    scan_fields("DroppedItemContainer",ITC,400);

    // détails : 3 DroppedItem, champs + chaîne Item
    printf("\n---- detail DroppedItem ----\n");
    int shown=0;
    for(uint64_t o : IT){
        uint32_t pref=r32(o+0x54); if(!pref||pref>2000000) continue;
        printf("\n  obj=0x%llx prefabID=%u\n",(unsigned long long)o,pref);
        float win[16]; if(rd(o+0x100,win,sizeof(win))){
            printf("   +0x100..0x13C : "); for(int i=0;i<16;i++) printf("%.2f ",win[i]); printf("\n"); }
        float bc[6]; if(rd(o+0x18C,bc,sizeof(bc))){
            printf("   +0x18C..0x1A4 : "); for(int i=0;i<6;i++) printf("%.2f ",bc[i]); printf("\n"); }
        uint64_t item=r64(o+0x208);
        printf("   +0x208 = 0x%llx (klass 0x%llx)\n",(unsigned long long)item,(unsigned long long)r64(item));
        // balayage des pointeurs->chaines sur l'objet ET sur l'item
        for(uint64_t base : {o,item}){
            if(base<0x1000000) continue;
            printf("   -- chaines depuis 0x%llx --\n",(unsigned long long)base);
            int f=0;
            for(uint64_t off=0x10; off<0x120; off+=8){ uint64_t p=r64(base+off); char s[200];
                if(p&&mstr(p,s,sizeof(s))){ printf("      +0x%03llx \"%s\"\n",(unsigned long long)off,s); f++; }
                else if(p>0x1000000&&r64(p)>0x1000000){ char s2[200];
                    for(uint64_t o2=0x10;o2<0x70;o2+=8){ uint64_t q=r64(p+o2); if(q&&mstr(q,s2,sizeof(s2))){
                        printf("      +0x%03llx -> 2>+0x%02llx \"%s\"\n",(unsigned long long)off,(unsigned long long)o2,s2); f++; } } } }
            if(!f) printf("      (aucune)\n");
        }
        if(++shown>=3) break;
    }
    printf("\ntotal %.1f s\n",(double)clock()/CLOCKS_PER_SEC-t0);
    return 0;
}
