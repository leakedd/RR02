// probe_ents — RECENSEMENT des entités réellement instanciées.
// Un objet vivant = en-tête (r64(a)==klass) + champ model (+0x1B8) -> objet de klass Model.
// Sert de test décisif : y a-t-il des DroppedItem en mémoire, et où ?
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
#include <unordered_map>
#include <unordered_set>
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
    std::unordered_set<std::string> want; std::vector<std::string> wl;
    { FILE* f=fopen("/tmp/entity_classes.txt","r"); if(!f){ printf("liste manquante\n"); return 1; }
      char line[256]; while(fgets(line,sizeof(line),f)){ size_t n=strcspn(line,"\r\n"); line[n]=0; if(n){ want.insert(line); wl.push_back(line);} } fclose(f); }
    want.insert("Model"); want.insert("PlayerModel");
    printf("classes d'entités à chercher : %zu\n",wl.size());
    pid_t PID=0; { FILE* f=popen("pgrep -x Rust | head -1","r"); char b[64]; if(f&&fgets(b,64,f)) PID=atoi(b); if(f)pclose(f); }
    if(!PID||task_for_pid(mach_task_self(),PID,&T)!=KERN_SUCCESS){ printf("task_for_pid KO\n"); return 1; }
    regions();
    const size_t CH=8u<<20; std::vector<unsigned char> buf(CH);
    // ---- passe A : klasses par nom ----
    std::map<std::string,uint64_t> K;
    for(auto&r:R){ for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+0x88<=(size_t)g;i+=8){ uint64_t X=c+i;
            if(*(uint64_t*)(buf.data()+i+0x78)!=X) continue;
            char nm[128]; uint64_t p=*(uint64_t*)(buf.data()+i+0x10); if(!p||!str_at(p,nm,sizeof(nm))) continue;
            if(want.count(nm)&&!K.count(nm)) K[nm]=X; } } }
    printf("passe A : %zu klasses trouvées / %zu attendues (%.1f s)\n",K.size(),want.size(),(double)clock()/CLOCKS_PER_SEC-t0);
    uint64_t kModel=K.count("Model")?K["Model"]:0; if(!kModel){ printf("klass Model absente\n"); return 1; }
    // ---- passe B : instances candidates (un seul parcours) ----
    std::unordered_map<uint64_t,int> kIdx; std::vector<std::string> kNm;
    for(auto&p:K){ kIdx[p.second]=(int)kNm.size(); kNm.push_back(p.first); }
    std::vector<uint64_t> candAddr; std::vector<int> candK;
    double tb=(double)clock()/CLOCKS_PER_SEC;
    for(auto&r:R){ for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+8<=(size_t)g;i+=8){ auto it=kIdx.find(*(uint64_t*)(buf.data()+i));
            if(it!=kIdx.end()){ candAddr.push_back(c+i); candK.push_back(it->second); } } } }
    printf("passe B : %zu références de klasses (%.1f s)\n",candAddr.size(),(double)clock()/CLOCKS_PER_SEC-tb);
    // ---- validation : en-tête + model -> klass Model ----
    std::vector<std::vector<uint64_t>> real(kNm.size());
    for(size_t i=0;i<candAddr.size();i++){
        uint64_t a=candAddr[i]; int k=candK[i];
        if(r64(a)!=K[kNm[k]]) continue;
        uint64_t m=r64(a+0x1B8); if(m<0x1000000) continue;
        if(r64(m)!=kModel) continue;
        real[k].push_back(a); }
    printf("\n===== RECENSEMENT (entités vivantes) =====\n");
    std::vector<std::pair<int,std::string>> cnt;
    for(size_t k=0;k<kNm.size();k++) if(real[k].size()) cnt.push_back({(int)real[k].size(),kNm[k]});
    std::sort(cnt.begin(),cnt.end(),[](auto&a,auto&b){return a.first>b.first;});
    int tot=0; for(auto&p:cnt) tot+=p.first;
    printf("types instanciés : %zu, entités totales : %d\n",cnt.size(),tot);
    for(auto&p:cnt) printf("  %-34s %5d\n",p.second.c_str(),p.first);
    // ---- positions des classes liées aux items ----
    printf("\n===== POSITIONS (classes 'items/loot') =====\n");
    const char* INTERET[]={"DroppedItem","WorldItem","DroppedItemContainer","LootContainer","BaseCorpse","PlayerCorpse","CollectibleEntity","ResourceEntity","StagedResourceEntity","HackableLockedCrate","SupplyDrop","BoxStorage"};
    for(const char* nm : INTERET){
        int k=-1; for(size_t i=0;i<kNm.size();i++) if(kNm[i]==nm) k=(int)i;
        if(k<0||real[k].empty()){ printf("  %-22s : 0 instance\n",nm); continue; }
        printf("  %-22s : %zu instances\n",nm,real[k].size());
        int s=0;
        for(uint64_t a : real[k]){
            float b118[3]={0},bc[3]={0},be[3]={0};
            rd(a+0x118,b118,12); rd(a+0x18C,bc,12); rd(a+0x198,be,12);
            printf("     obj=0x%llx  v0x118=(%.1f %.1f %.1f)  bounds.c=(%.1f %.1f %.1f) ext=(%.2f %.2f %.2f)\n",
                (unsigned long long)a,b118[0],b118[1],b118[2],bc[0],bc[1],bc[2],be[0],be[1],be[2]);
            if(++s>=8) break; }
    }
    printf("\ntotal %.1f s\n",(double)clock()/CLOCKS_PER_SEC-t0);
    return 0;
}
