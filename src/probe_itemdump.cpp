// probe_itemdump — champs de l'objet Item réel (pour trouver l'ItemDefinition / un nom)
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <unistd.h>
#include <functional>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>
#include <string>
#include <thread>
#include <atomic>
#include <algorithm>
#include <cmath>

static task_t T; static pid_t PID;
struct Reg{ uint64_t a,sz; };
static std::vector<Reg> RW;
static bool rd(uint64_t a,void*b,size_t n){ mach_vm_size_t g=0;
  return mach_vm_read_overwrite(T,a,n,(mach_vm_address_t)b,&g)==KERN_SUCCESS && g==n; }
static uint64_t r64(uint64_t a){ uint64_t v=0; rd(a,&v,8); return v; }
static uint32_t r32(uint64_t a){ uint32_t v=0; rd(a,&v,4); return v; }
static bool strn(uint64_t a,char*o,size_t n){ if(!rd(a,o,n-1)) return false; o[n-1]=0; if(!o[0]) return false;
  for(int i=0;o[i];i++) if((unsigned char)o[i]<0x20||(unsigned char)o[i]>0x7e) return false; return true; }
static std::string kname(uint64_t o){ if(o<0x1000000) return ""; uint64_t k=r64(o); if(k<0x1000000) return "";
  char b[80]={0}; uint64_t np=r64(k+0x10); if(!np||!strn(np,b,sizeof(b))) return ""; return std::string(b); }
static std::string mstr(uint64_t sp){ if(sp<0x1000000) return ""; int len=(int)r32(sp+0x10); char b[160]={0};
  if(len>0&&len<150&&strn(sp+0x14,b,(size_t)len+1)) return std::string(b);
  if(strn(sp+0x14,b,159)) return std::string(b); return ""; }

int main(){
  PID=0; { FILE* f=popen("pgrep -x Rust | head -1","r"); char b[64]; if(f&&fgets(b,64,f)) PID=atoi(b); if(f)pclose(f); }
  if(!PID){ printf("Rust absent\n"); return 1; }
  if(task_for_pid(mach_task_self(),PID,&T)!=KERN_SUCCESS){ printf("task_for_pid KO\n"); return 1; }
  mach_vm_address_t a=0x100000000ULL;
  for(;;){ mach_vm_address_t q=a; mach_vm_size_t sz=0; vm_region_basic_info_data_64_t bi; mach_port_t ob=0;
    mach_msg_type_number_t ci=VM_REGION_BASIC_INFO_COUNT_64;
    if(mach_vm_region(T,&q,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&bi,&ci,&ob)!=KERN_SUCCESS) break;
    if(sz>0&&(bi.protection&VM_PROT_READ)&&(bi.protection&VM_PROT_WRITE)) RW.push_back({q,sz});
    if(q+sz<=a) break; a=q+sz; }
  printf("regions RW=%zu\n",RW.size()); fflush(stdout);

  std::atomic<uint64_t> kd{0},kit{0};
  auto scan=[&](std::function<void(unsigned char*,uint64_t,size_t)> body){
    int nt=8; std::atomic<size_t> idx{0}; std::vector<std::thread> th;
    for(int t=0;t<nt;t++) th.emplace_back([&](){
      const size_t CH=8u<<20; std::vector<unsigned char> buf(CH);
      for(;;){ size_t i=idx++; if(i>=RW.size()) break; const Reg& r=RW[i];
        for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
          mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
          body(buf.data(),c,(size_t)g); } } });
    for(auto&x:th) x.join(); };

  // passe 1 : klasses
  scan([&](unsigned char* buf,uint64_t cur,size_t got){
    if(kd&&kit) return;
    for(size_t i=0;i+0x88<=got;i+=8){ uint64_t X=cur+i;
      if(*(uint64_t*)(buf+i+0x78)!=X) continue;
      uint64_t p=*(uint64_t*)(buf+i+0x10); if(!p) continue; char nm[128];
      if(!strn(p,nm,sizeof(nm))) continue;
      if(!kd && !strcmp(nm,"DroppedItem")) kd=X;
      else if(!kit && !strcmp(nm,"%842e6b2f32a12d6d9f1a80e7de9e9902d2f3ecdc")) kit=X; } });
  printf("klass DroppedItem=0x%llx Item=0x%llx\n",(unsigned long long)kd.load(),(unsigned long long)kit.load()); fflush(stdout);
  uint64_t KD=kd.load();

  // passe 2 : refs DroppedItem
  std::vector<uint64_t> refs; std::mutex M;
  scan([&](unsigned char* buf,uint64_t cur,size_t got){
    std::vector<uint64_t> loc;
    for(size_t i=0;i+8<=got;i+=8) if(*(uint64_t*)(buf+i)==KD) loc.push_back(cur+i);
    if(!loc.empty()){ std::lock_guard<std::mutex> g(M); for(uint64_t o:loc) refs.push_back(o); } });
  printf("candidats=%zu\n",refs.size()); fflush(stdout);

  int shown=0;
  for(uint64_t o : refs){
    if(shown>=3) break;
    if(r64(o)!=KD) continue;
    if(kname(r64(o+0x210))!="GameObjectRef") continue;
    uint64_t it=r64(o+0x208);
    if(kname(it)!="%842e6b2f32a12d6d9f1a80e7de9e9902d2f3ecdc") continue;
    shown++;
    printf("\n=== DroppedItem 0x%llx -> Item 0x%llx ===\n",(unsigned long long)o,(unsigned long long)it);
    uint64_t q[96]; if(!rd(it,q,sizeof(q))){ printf("  (item illisible)\n"); continue; }
    for(int j=2;j<96;j++){
      uint64_t v=q[j]; if(v<0x1000000) { if(v) printf("  +0x%03x 0x%llx (int)\n",j*8,(unsigned long long)v); continue; }
      std::string kn=kname(v);
      if(kn.empty()){ printf("  +0x%03x 0x%llx ?\n",j*8,(unsigned long long)v); continue; }
      printf("  +0x%03x 0x%llx %s",j*8,(unsigned long long)v,kn.c_str());
      if(kn=="String"){ std::string s=mstr(v); if(!s.empty()) printf("  \"%s\"",s.c_str()); }
      if(kn=="ItemDefinition"){ std::string s=mstr(r64(v+0x28));
        printf("  >> ItemDefinition itemid=%u shortname=\"%s\"",r32(v+0x20),s.c_str()); }
      printf("\n");
    }
    // dump de l'ItemDefinition : ou vit le shortname dans CE build ?
    for(int j=9;j<96;j++){ uint64_t v=q[j]; if(v<0x1000000) continue;
      if(kname(v)!="ItemDefinition") continue;
      printf("  --- ItemDefinition @0x%llx ---\n",(unsigned long long)v);
      uint64_t d[64]; if(!rd(v,d,sizeof(d))) continue;
      for(int j2=2;j2<64;j2++){ uint64_t w=d[j2]; if(w<0x1000000) continue;
        std::string kn2=kname(w); if(kn2.empty()) continue;
        printf("       +0x%03x %s",j2*8,kn2.c_str());
        if(kn2=="String"){ std::string s=mstr(w); if(!s.empty()) printf("  \"%s\"",s.c_str()); }
        else if(kn2=="Phrase"){ std::string s=mstr(r64(w+0x10)); if(!s.empty()) printf("  phrase=\"%s\"",s.c_str()); }
        printf("\n"); }
      uint64_t z=r64(v+0x10); printf("       (def+0x10 -> 0x%llx)\n",(unsigned long long)z); }
  }
  printf("\nitems dumps=%d\n",shown);
  return 0;
}
