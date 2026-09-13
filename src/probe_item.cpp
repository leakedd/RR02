// probe_item — instances de DroppedItem : prefabID, position (pistes multiples), nom de l'item
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <cmath>
#include <vector>
#include <algorithm>

static task_t T;
static bool rd(uint64_t a,void*b,size_t n){ mach_vm_size_t g=0;
    return mach_vm_read_overwrite(T,a,n,(mach_vm_address_t)b,&g)==KERN_SUCCESS && g==n; }
static uint64_t r64(uint64_t a){ uint64_t v=0; rd(a,&v,8); return v; }
static uint32_t r32(uint64_t a){ uint32_t v=0; rd(a,&v,4); return v; }
static bool str_at(uint64_t a,char*out,size_t n){ if(!rd(a,out,n-1)) return false; out[n-1]=0; if(!out[0]) return false;
    for(size_t i=0;out[i];i++) if((unsigned char)out[i]<0x20||(unsigned char)out[i]>0x7e) return false; return true; }
// chaine managée IL2CPP : obj -> length@+0x10, chars utf16/utf8 @+0x14
static bool mstr(uint64_t p,char*out,size_t n){
    if(p<0x1000000) return false;
    uint32_t len=r32(p+0x10); if(len<1||len>120) return false;
    char buf[256]; if(!rd(p+0x14,buf,sizeof(buf))) return false;   // essai utf8
    size_t k=0; for(;k<len&&k<n-1;k++){ unsigned char c=buf[k]; if(c<0x20||c>0x7e) break; }
    if(k>=len&&k>0){ memcpy(out,buf,k); out[k]=0; return true; }
    // essai utf16
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
int main(){
    pid_t PID=0; { FILE* f=popen("pgrep -x Rust | head -1","r"); char b[64]; if(f&&fgets(b,64,f)) PID=atoi(b); if(f)pclose(f); }
    if(!PID||task_for_pid(mach_task_self(),PID,&T)!=KERN_SUCCESS){ printf("KO\n"); return 1; }
    regions();
    uint64_t kd=find_klass("DroppedItem"), km=find_klass("Model"), kc=find_klass("DroppedItemContainer"), kw=find_klass("WorldItem");
    printf("klass DroppedItem=0x%llx Model=0x%llx DroppedItemContainer=0x%llx WorldItem=0x%llx | regions=%zu\n",
        (unsigned long long)kd,(unsigned long long)km,(unsigned long long)kc,(unsigned long long)kw,R.size());
    if(!kd) return 1;
    const size_t CH=8u<<20; std::vector<unsigned char> buf(CH);
    std::vector<uint64_t> cand;
    for(auto&r:R){ for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
        mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
        for(size_t i=0;i+8<=(size_t)g;i+=8) if(*(uint64_t*)(buf.data()+i)==kd) cand.push_back(c+i); } }
    printf("candidats (valeur == klass DroppedItem): %zu\n",cand.size());

    int shown=0;
    for(uint64_t o : cand){
        uint64_t model=r64(o+0x1B8);
        uint32_t pref=r32(o+0x54);
        if(!model) continue;
        if(km && r64(model)!=km) continue;                    // model->klass == Model
        uint64_t root=r64(model+0x28);                        // Model.rootBone (Transform)
        float v118[3]={0,0,0}; rd(o+0x118,v118,12);
        float bc[3]={0,0,0};    rd(o+0x18C,bc,12);            // bounds.center
        float be[3]={0,0,0};    rd(o+0x198,be,12);            // bounds.extents
        uint64_t native=r64(root+0x10);                       // m_CachedPtr probable
        uint64_t native2=r64(root+0x18);
        printf("\n=== instance 0x%llx | prefabID=%u | model=0x%llx rootBone=0x%llx (klass=0x%llx)\n",
            (unsigned long long)o,pref,(unsigned long long)model,(unsigned long long)root,(unsigned long long)r64(root));
        printf("    v@0x118    = %.2f %.2f %.2f\n",v118[0],v118[1],v118[2]);
        printf("    bounds.c   = %.2f %.2f %.2f   ext=%.2f %.2f %.2f\n",bc[0],bc[1],bc[2],be[0],be[1],be[2]);
        printf("    r64(root+0x10)=0x%llx  r64(root+0x18)=0x%llx\n",(unsigned long long)native,(unsigned long long)native2);
        // dump des premiers floats du natif (pour repérer la position monde)
        for(uint64_t np : {native,native2}){
            if(np<0x1000000) continue;
            float f[24]; if(!rd(np,f,sizeof(f))) continue;
            printf("    48 premiers floats de 0x%llx :\n      ",(unsigned long long)np);
            for(int i=0;i<24;i++){ printf("%.1f ",f[i]); if(i%6==5) printf("\n      "); }
            printf("\n");
        }
        // noms : strings joignables depuis l'objet item (WorldItem+0x208) et depuis l'entite
        uint64_t item=r64(o+0x208);
        printf("    item=0x%llx\n",(unsigned long long)item);
        int found=0;
        for(uint64_t base : {item,o}){
            if(base<0x1000000) continue;
            for(uint64_t off=0x10; off<0x100; off+=8){
                uint64_t p=r64(base+off); char s[160];
                if(p&&mstr(p,s,sizeof(s))){ printf("      [0x%llx+0x%02llx] -> \"%s\"\n",(unsigned long long)base,(unsigned long long)off,s); found++; }
            }
        }
        if(!found) printf("      (aucune chaine directe)\n");
        if(++shown>=6) break;
    }
    printf("\ninstances montreés: %d\n",shown);
    return 0;
}
