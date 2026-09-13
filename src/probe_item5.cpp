// probe_item5 — instances RÉELLES par test structurel (champ -> objet de klass connue),
// puis découverte statistique de la position, puis nom de l'item via klass Item.
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
#include <numeric>
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
static const int WIN=0x340;
static bool ok3(float x,float y,float z){
    if(!std::isfinite(x)||!std::isfinite(y)||!std::isfinite(z)) return false;
    if(fabsf(x)>6000||fabsf(z)>6000) return false;
    if(y<-60||y>500) return false;
    if(fabsf(x)+fabsf(z)<1.0f) return false; return true;
}
static std::map<int,int> v3scan(uint64_t o){
    std::map<int,int> c; std::vector<unsigned char> w(WIN);
    if(!rd(o,w.data(),WIN)) return c;
    for(int off=0x10;off<=WIN-12;off+=4){ float x,y,z;
        memcpy(&x,w.data()+off,4); memcpy(&y,w.data()+off+4,4); memcpy(&z,w.data()+off+8,4);
        if(ok3(x,y,z)) c[off]++; }
    return c;
}
static void addhist(std::map<int,int>&dst,const std::map<int,int>&src){ for(auto&p:src) dst[p.first]+=p.second; }
static void topp(std::map<int,int>&h,int tot,const char*title,int maxk){
    std::vector<std::pair<int,int>> v(h.begin(),h.end());
    std::sort(v.begin(),v.end(),[](auto&a,auto&b){return a.second>b.second;});
    printf("\n%s (témoin : %d valeurs)\n",title,tot);
    int k=0; for(auto&p:v){ printf("   +0x%03x : %5d/%d\n",p.first,p.second,tot); if(++k>=maxk) break; }
}
int main(){
    setvbuf(stdout,NULL,_IONBF,0);
    double t0=(double)clock()/CLOCKS_PER_SEC;
    pid_t PID=0; { FILE* f=popen("pgrep -x Rust | head -1","r"); char b[64]; if(f&&fgets(b,64,f)) PID=atoi(b); if(f)pclose(f); }
    if(!PID||task_for_pid(mach_task_self(),PID,&T)!=KERN_SUCCESS){ printf("task_for_pid KO\n"); return 1; }
    regions();
    const char* WANT[]={"PlayerModel","Model","DroppedItem","DroppedItemContainer","BasePlayer","Item","ItemDefinition"};
    const int NW=7; uint64_t K[NW]={0};
    const size_t CH=8u<<20; std::vector<unsigned char> buf(CH);
    for(auto&r:R){ for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+0x88<=(size_t)g;i+=8){ uint64_t X=c+i;
            if(*(uint64_t*)(buf.data()+i+0x78)!=X) continue;
            char nm[128]; uint64_t p=*(uint64_t*)(buf.data()+i+0x10); if(!p||!str_at(p,nm,sizeof(nm))) continue;
            for(int k=0;k<NW;k++) if(!K[k]&&!strcmp(nm,WANT[k])) K[k]=X; } } }
    for(int k=0;k<NW;k++) printf("klass %-20s = 0x%llx\n",WANT[k],(unsigned long long)K[k]);
    std::vector<uint64_t> *hit=new std::vector<uint64_t>[NW];
    for(auto&r:R){ for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+8<=(size_t)g;i+=8){ uint64_t v=*(uint64_t*)(buf.data()+i);
            for(int k=0;k<NW;k++) if(K[k]&&v==K[k]){ hit[k].push_back(c+i); break; } } } }

    printf("\n== [A] TEMOIN PlayerModel : candidats=%zu, dont position saine @+0x2F8 :\n",hit[0].size());
    int goodpm=0; std::vector<uint64_t> goodpms;
    for(uint64_t a:hit[0]){ float v[3]; if(!rd(a+0x2F8,v,12)) continue;
        if(ok3(v[0],v[1],v[2])){ goodpm++; if(goodpms.size()<5) goodpms.push_back(a); } }
    printf("   -> %d PlayerModel réels\n",goodpm);
    for(uint64_t a:goodpms){ float v[3]; rd(a+0x2F8,v,12); printf("      0x%llx pos=(%.1f %.1f %.1f)\n",(unsigned long long)a,v[0],v[1],v[2]); }

    // ---------- BasePlayer -> Model ----------
    printf("\n== [B] BasePlayer -> Model (offset ?) : %zu candidats\n",hit[4].size());
    std::map<int,int> histBP; int nbp=0;
    for(uint64_t a:hit[4]){ if(r64(a)!=K[4]) continue; nbp++;
        for(int off=0x10;off<=WIN-8;off+=8){ uint64_t p=r64(a+off); if(p>0x1000000&&r64(p)==K[1]){ histBP[off]++; break; } } }
    printf("   objets BP (en-tete valide) = %d\n",nbp);
    { std::vector<std::pair<int,int>> v(histBP.begin(),histBP.end());
      std::sort(v.begin(),v.end(),[](auto&a,auto&b){return a.second>b.second;});
      for(int i=0;i<(int)v.size()&&i<6;i++) printf("   offset Model +0x%03x : %d BP\n",v[i].first,v[i].second); }

    // ---------- DroppedItem / DroppedItemContainer -> Model + Item ----------
    auto itof=[&](int k,const char*label){
        std::map<int,int> hM,hI; std::vector<uint64_t> real; int hdr=0;
        for(uint64_t a:hit[k]){ if(r64(a)!=K[k]) continue; hdr++;
            int moff=-1,ioff=-1;
            for(int off=0x10;off<=WIN-8;off+=8){ uint64_t p=r64(a+off); if(p<0x1000000) continue;
                uint64_t c=r64(p); if(c==K[1]&&moff<0) moff=off; if(c==K[5]&&ioff<0) ioff=off; }
            if(moff>=0) hM[moff]++; if(ioff>=0) hI[ioff]++;
            if(moff>=0||ioff>=0) real.push_back(a); }
        printf("\n== [C] %s : en-tetes=%d, avec Model=%zu, avec Item=%zu\n",label,hdr,
            hM.empty()?0:(size_t)std::accumulate(hM.begin(),hM.end(),0,[](int s,auto&p){return s+p.second;}),
            hI.empty()?0:(size_t)std::accumulate(hI.begin(),hI.end(),0,[](int s,auto&p){return s+p.second;}));
        auto show=[&](std::map<int,int>&h,const char*nm){ std::vector<std::pair<int,int>> v(h.begin(),h.end());
            std::sort(v.begin(),v.end(),[](auto&a,auto&b){return a.second>b.second;});
            for(int i=0;i<(int)v.size()&&i<5;i++) printf("   offset %s +0x%03x : %d objets\n",nm,v[i].first,v[i].second); };
        show(hM,"Model"); show(hI,"Item");
        return real;
    };
    std::vector<uint64_t> rIT=itof(2,"DroppedItem");
    std::vector<uint64_t> rITC=itof(3,"DroppedItemContainer");

    // ---------- positions des items réels (statistique) ----------
    std::map<int,int> hpos; for(uint64_t a:rIT) addhist(hpos,v3scan(a));
    topp(hpos,(int)rIT.size(),"== [D] DroppedItem réels : Vector3 plausibles par offset",8);

    // ---------- noms ----------
    printf("\n== [E] noms d'items (objets Item trouvés dans les items réels)\n");
    std::map<std::string,int> names;
    for(uint64_t a : rIT){
        for(int off=0x10;off<=WIN-8;off+=8){ uint64_t p=r64(a+off); if(p<0x1000000||r64(p)!=K[5]) continue;
            for(uint64_t o1=0x10;o1<0x80;o1+=8){ uint64_t q=r64(p+o1); char s[200];
                if(q&&mstr(q,s,sizeof(s))) names[s]++;
                else if(q>0x1000000&&r64(q)>0x1000000) for(uint64_t o2=0x10;o2<0x70;o2+=8){
                    uint64_t t=r64(q+o2); char s2[200]; if(t&&mstr(t,s2,sizeof(s2))) names[s2]++; } } } }
    std::vector<std::pair<std::string,int>> nv(names.begin(),names.end());
    std::sort(nv.begin(),nv.end(),[](auto&a,auto&b){return a.second>b.second;});
    for(int i=0;i<(int)nv.size()&&i<25;i++) printf("   \"%s\" x%d\n",nv[i].first.c_str(),nv[i].second);

    printf("\n== [F] 8 items réels : champs bruts\n");
    int sh=0;
    for(uint64_t a : rIT){ printf("   obj=0x%llx prefabID=%u flags=0x%x\n",(unsigned long long)a,r32(a+0x54),r32(a+0x1C4));
        float f[12]; if(rd(a+0x110,f,sizeof(f))){ printf("      +0x110..0x13C : "); for(int i=0;i<12;i++) printf("%.1f ",f[i]); printf("\n"); }
        if(++sh>=8) break; }
    printf("\ntotal %.1f s\n",(double)clock()/CLOCKS_PER_SEC-t0);
    return 0;
}
