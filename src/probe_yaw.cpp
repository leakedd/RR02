// probe_yaw — trouve le YAW (cap) : caméra (vue) + joueurs (corps), et identifie « moi ».
//  - klasses par nom : BasePlayer, PlayerModel, MainCamera
//  - caméra : MainCamera.static_fields (klass+0xB8) -> champs 0x00..0x40 -> Transform / PAT A
//  - joueurs : position (PlayerModel+0x2F8) + enregistrement de transform natif 32 o :
//      [Vector3 position | Quaternion rotation | float echelle] lu a d+0x90 (d = r64(r64(o+0x90)))
//  - echantillonne ~45 s (300 ms) pour voir le yaw bouger quand on tourne en jeu
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
#include <thread>
#include <atomic>
#include <mutex>
#include <algorithm>
#include <functional>

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
static bool sane3(const float*v){ return std::isfinite(v[0])&&std::isfinite(v[1])&&std::isfinite(v[2])
  && fabsf(v[0])<6000&&fabsf(v[2])<6000&&v[1]>0.2f&&v[1]<900.0f&&!(fabsf(v[0])<1&&fabsf(v[2])<1); }

// quaternion Unity (x,y,z,w) -> yaw en degres (0 = nord/+Z, 90 = est/+X)
static float yaw_of(float x,float y,float z,float w){
  float fx = 2.0f*(x*z + w*y);
  float fz = 1.0f - 2.0f*(x*x + y*y);
  return atan2f(fx,fz)*180.0f/3.14159265f;
}
static bool valid_quat(const float*q){ float n=q[0]*q[0]+q[1]*q[1]+q[2]*q[2]+q[3]*q[3];
  return std::isfinite(n)&&n>0.90f&&n<1.10f; }

// transform natif d'une entite (PAT A) -> d ; enregistrement 32 o lu a d+0x90
static bool nat_rec(uint64_t o,float*rec8){ uint64_t h=r64(o+0x90); if(h<0x1000000||h>0x300000000000ULL) return false;
  uint64_t d=r64(h); if(d<0x1000000||d>0x300000000000ULL) return false;
  return rd(d+0x90,rec8,32); }

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
  printf("RW=%zu\n",RW.size()); fflush(stdout);
  std::atomic<uint64_t> kb{0},km{0},kc{0};
  { int nt=6; std::atomic<size_t> idx{0}; std::vector<std::thread> th;
    for(int t=0;t<nt;t++) th.emplace_back([&](){
      const size_t CH=8u<<20; std::vector<unsigned char> buf(CH);
      for(;;){ size_t i=idx++; if(i>=RW.size()) break; const Reg& r=RW[i];
        for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
          mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
          if(kb&&km&&kc) return;
          for(size_t j=0;j+0x88<=g;j+=8){ uint64_t X=c+j;
            if(*(uint64_t*)(buf.data()+j+0x78)!=X) continue;
            uint64_t p=*(uint64_t*)(buf.data()+j+0x10); if(!p) continue;
            char nm[96]; uint64_t np=r64(p); if(!np||!strn(np,nm,sizeof(nm))) continue;
            if(!kb && !strcmp(nm,"BasePlayer")) kb=X;
            else if(!km && !strcmp(nm,"PlayerModel")) km=X;
            else if(!kc && !strcmp(nm,"MainCamera")) kc=X; } } } });
    for(auto&x:th) x.join(); }
  printf("klass BasePlayer=0x%llx PlayerModel=0x%llx MainCamera=0x%llx\n",
    (unsigned long long)kb.load(),(unsigned long long)km.load(),(unsigned long long)kc.load()); fflush(stdout);
  if(!kb||!km){ printf("klasses manquantes\n"); return 1; }

  // --- resolution camera ---
  uint64_t KC=kc.load();
  printf("--- camera ---\n");
  uint64_t sf = KC? r64(KC+0xB8) : 0;
  printf("MainCamera static_fields=0x%llx\n",(unsigned long long)sf);
  std::vector<uint64_t> camcand;
  if(sf){ for(int i=0;i<8;i++){ uint64_t v=r64(sf+i*8); if(v>=0x1000000&&v<0x300000000000ULL)
    printf("  sf+0x%02x = 0x%llx  %s\n",i*8,(unsigned long long)v,kname(v).c_str()); } }
  if(sf){ for(int i=0;i<8;i++){ uint64_t v=r64(sf+i*8); if(v<0x1000000) continue;
    if(kname(v)=="Transform") { camcand.push_back(v); continue; }
    // objet composant : chercher un Transform dans ses champs
    uint64_t q[48]; if(!rd(v,q,sizeof(q))) continue;
    for(int j=2;j<48;j++){ uint64_t w=q[j]; if(w<0x1000000) continue;
      if(kname(w)=="Transform"){ printf("  -> composant 0x%llx contient Transform 0x%llx (champ +0x%02x)\n",
        (unsigned long long)v,(unsigned long long)w,j*8); camcand.push_back(w); break; } } } }
  auto cam_read=[&](float*pos,float*yaw,int*src)->bool{
    for(size_t i=0;i<camcand.size();i++){ uint64_t t=camcand[i];
      // Transform IL2CPP -> +0x10 natif -> +0x28 struct -> +0x90 enregistrement
      uint64_t nat=r64(t+0x10); if(nat<0x1000000) continue; uint64_t st=r64(nat+0x28); if(st<0x1000000) continue;
      float rec[8]; if(!rd(st+0x90,rec,32)) continue;
      if(!sane3(rec)) continue;
      if(valid_quat(rec+3)){ memcpy(pos,rec,12); *yaw=yaw_of(rec[3],rec[4],rec[5],rec[6]); *src=(int)i; return true; } }
    return false; };

  // --- refs joueurs ---
  std::vector<uint64_t> refs; std::mutex M; uint64_t KB=kb.load();
  { int nt=6; std::atomic<size_t> idx{0}; std::vector<std::thread> th;
    for(int t=0;t<nt;t++) th.emplace_back([&](){
      const size_t CH=8u<<20; std::vector<unsigned char> buf(CH); std::vector<uint64_t> loc;
      for(;;){ size_t i=idx++; if(i>=RW.size()) break; const Reg& r=RW[i];
        for(uint64_t c=r.a;c<r.a+r.sz;c+=CH){ size_t wn=(size_t)std::min<uint64_t>(CH,r.a+r.sz-c);
          mach_vm_size_t g=0; if(mach_vm_read_overwrite(T,c,wn,(mach_vm_address_t)buf.data(),&g)!=KERN_SUCCESS) continue;
          loc.clear();
          for(size_t j=0;j+8<=g;j+=8) if(*(uint64_t*)(buf.data()+j)==KB) loc.push_back(c+j);
          if(!loc.empty()){ std::lock_guard<std::mutex> g2(M); for(uint64_t o:loc) refs.push_back(o); } } } });
    for(auto&x:th) x.join(); }
  std::vector<uint64_t> ok;
  for(uint64_t o:refs){ if(r64(o)!=KB) continue; uint64_t m=r64(o+0x328); if(!m||r64(m)!=km.load()) continue;
    float v[3]; if(!rd(m+0x2F8,v,12)||!sane3(v)) continue; ok.push_back(o); }
  printf("joueurs valides=%zu\n",ok.size()); fflush(stdout);

  printf("\n=== echantillonnage 45 s (300 ms) — TOURNE SUR TOI-MEME en jeu ===\n");
  printf("t | cam_pos | cam_yaw | me_id | me_pos | me_yaw | corps->cap | d_cam\n");
  for(int t=0;t<150;t++){
    float cp[3]={0,0,0}, cy=0; int src=-1;
    bool hascam=cam_read(cp,&cy,&src);
    uint64_t me=0, best=~0ULL; float mp[3]={0,0,0}, my=0;
    for(uint64_t o:ok){ float v[3]; uint64_t m=r64(o+0x328); if(!m) continue; if(!rd(m+0x2F8,v,12)) continue;
      float rec[8]; float y=0; bool hy=false;
      if(nat_rec(o,rec)&&sane3(rec)&&valid_quat(rec+3)){ y=yaw_of(rec[3],rec[4],rec[5],rec[6]); hy=true; }
      if(hascam){ float d=sqrtf((v[0]-cp[0])*(v[0]-cp[0])+(v[2]-cp[2])*(v[2]-cp[2]));
        if(d<best){ best=(uint64_t)(d*1000.0f); me=o; memcpy(mp,v,12); my=y; } }
      if(t%10==0){ /* trace périodique de tous les joueurs proches */ }
      if(hy && t%10==0){
        float d = hascam? sqrtf((v[0]-cp[0])*(v[0]-cp[0])+(v[2]-cp[2])*(v[2]-cp[2])) : 0;
        if(d<40.0f) printf("   P 0x%llx pos=(%.1f,%.1f,%.1f) yaw=%.1f d_cam=%.1fm\n",
          (unsigned long long)o,v[0],v[1],v[2],y,d); }
    }
    if(t%4==0){
      printf("t=%3ds | cam=(%.1f,%.1f,%.1f) yaw=%7.1f src=%d | me=(0x%llx) pos=(%.1f,%.1f,%.1f) yaw=%7.1f | d=%.2fm\n",
        3*t/10, cp[0],cp[1],cp[2],cy,src,(unsigned long long)me,mp[0],mp[1],mp[2],my,best==~0ULL?-1.0f:best/1000.0f);
      fflush(stdout); }
    usleep(300000);
  }
  return 0;
}
