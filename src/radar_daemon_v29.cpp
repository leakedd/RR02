// radar_daemon_v29 — chaîne validée 12/09/2026 (Rust Unity 6000.3.15f1 / metadata v39)
//   1) klass PlayerModel : scan RW, auto-référence r64(X+0x78)==X  puis  name@+0x10 == "PlayerModel"
//   2) instances : qword == klass (obj+0x00 = klass)
//   3) position : obj+0x2F8 (Vector3)
// sortie /tmp/rr02_radar.json  {"ts":..,"count":N,"players":[{"x":..,"y":..,"z":..},..]}
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <unistd.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cstdint>
#include <vector>
#include <cmath>
#include <ctime>
#include <algorithm>

static task_t T; static pid_t PID;
static const char* OUT = "/tmp/rr02_radar.json";

static bool rd(uint64_t a, void* b, size_t n){
    mach_vm_size_t g=0;
    return mach_vm_read_overwrite(T,a,n,(mach_vm_address_t)b,&g)==KERN_SUCCESS && g==n;
}
static uint64_t r64(uint64_t a){ uint64_t v=0; rd(a,&v,8); return v; }
static bool name_of(uint64_t a, char* out, size_t n){
    uint64_t p=r64(a); if(!p) return false;
    if(!rd(p,out,n-1)) return false;
    out[n-1]=0; return true;
}

// parcourt les régions RW ; callback sur chaque buffer
template<typename F>
static void scan_rw(F cb){
    mach_vm_address_t a=0x100000000ULL;
    for(;;){
        mach_vm_address_t q=a; mach_vm_size_t sz=0;
        vm_region_basic_info_data_64_t bi; mach_port_t ob=0;
        mach_msg_type_number_t ci=VM_REGION_BASIC_INFO_COUNT_64;
        if(mach_vm_region(T,&q,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&bi,&ci,&ob)!=KERN_SUCCESS) break;
        if(sz>0 && (bi.protection&VM_PROT_READ) && (bi.protection&VM_PROT_WRITE)){
            const size_t CH=4u<<20; std::vector<unsigned char> buf(CH);
            for(uint64_t cur=q; cur<q+sz; cur+=CH){
                size_t wn=(size_t)std::min<uint64_t>(CH, q+sz-cur);
                mach_vm_size_t got=0;
                if(mach_vm_read_overwrite(T,cur,wn,(mach_vm_address_t)buf.data(),&got)!=KERN_SUCCESS) continue;
                cb(cur,buf.data(),(size_t)got);
            }
        }
        if(q+sz<=a) break; a=q+sz;
    }
}

static uint64_t find_klass(const char* want){
    uint64_t found=0;
    scan_rw([&](uint64_t cur,unsigned char* buf,size_t got){
        if(found) return;
        if(got < 0x80) return;
        for(size_t i=0;i+0x88<=got;i+=8){
            uint64_t X=cur+i;
            if(*(uint64_t*)(buf+i+0x78)!=X) continue;
            char nm[128]; if(!name_of(X+0x10,nm,sizeof(nm))) continue;
            if(strcmp(nm,want)==0){ found=X; return; }
        }
    });
    return found;
}

static void find_instances(uint64_t klass, std::vector<uint64_t>& out){
    out.clear();
    scan_rw([&](uint64_t cur,unsigned char* buf,size_t got){
        for(size_t i=0;i+8<=got;i+=8)
            if(*(uint64_t*)(buf+i)==klass) out.push_back(cur+i);
    });
}

int main(){
    PID=0;
    { FILE* f=popen("pgrep -x Rust | head -1","r"); char b[64]; if(f&&fgets(b,64,f)) PID=atoi(b); if(f)pclose(f); }
    if(!PID){ printf("Rust absent\n"); return 1; }
    if(task_for_pid(mach_task_self(),PID,&T)!=KERN_SUCCESS){ printf("task_for_pid KO\n"); return 1; }
    printf("[v29] pid=%d\n",PID); fflush(stdout);

    uint64_t klass=0; std::vector<uint64_t> inst;
    time_t t_rescan=0;

    for(;;){
        if(time(0)>=t_rescan){
            uint64_t k=find_klass("PlayerModel");
            if(k){ klass=k; find_instances(klass,inst); }
            t_rescan=time(0)+120;
            printf("[v29] klass=0x%llx instances=%zu\n",(unsigned long long)klass,inst.size()); fflush(stdout);
        }
        if(!klass){ sleep(2); t_rescan=0; continue; }

        // positions
        std::vector<float> pos;
        for(uint64_t o : inst){
            float v[3];
            if(!rd(o+0x2F8,v,12)) continue;
            if(!std::isfinite(v[0])||!std::isfinite(v[1])||!std::isfinite(v[2])) continue;
            if(fabsf(v[0])>6000||fabsf(v[2])>6000) continue;
            if(v[1]<=0.5f||v[1]>900.0f) continue;            // élimine le placeholder (y=0)
            if(fabsf(v[0])<1.0f&&fabsf(v[2])<1.0f) continue;
            pos.push_back(v[0]); pos.push_back(v[1]); pos.push_back(v[2]);
        }

        char tmp[256]; snprintf(tmp,sizeof(tmp),"%s.tmp",OUT);
        FILE* f=fopen(tmp,"w"); if(!f){ sleep(1); continue; }
        fprintf(f,"{\"ts\":%ld,\"count\":%zu,\"players\":[",(long)time(0),pos.size()/3);
        for(size_t i=0;i+2<pos.size();i+=3)
            fprintf(f,"%s{\"x\":%.1f,\"y\":%.1f,\"z\":%.1f}", i?" ,":"", pos[i],pos[i+1],pos[i+2]);
        fprintf(f,"]}");
        fclose(f); rename(tmp,OUT);
        sleep(1);
    }
}
