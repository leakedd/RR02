// RR02/scan_pm.c — Scan PlayerModel for real position offsets
#include <stdio.h>
#include <stdint.h>
#include <math.h>
#include <string.h>
#include <unistd.h>
#include <mach/mach.h>
#include <libproc.h>

task_t g_task;
int read_mem(uint64_t a, void*b, size_t s) { vm_size_t g=0; return vm_read_overwrite(g_task,a,s,(vm_address_t)b,&g)==0&&g==s; }
uint64_t r64(uint64_t a) { uint64_t v=0; read_mem(a,&v,8); return v; }
float rf(uint64_t a) { float v=0; read_mem(a,&v,4); return v; }
int vptr(uint64_t p) { return p>0x100000ULL&&p<0x800000000000ULL; }

int main() {
    pid_t pids[4096]; int n=proc_listpids(PROC_ALL_PIDS,0,pids,sizeof(pids));
    pid_t pid=-1;
    for(int i=0;i<n/(int)sizeof(pid_t);i++){
        char p[1024];
        if(proc_pidpath(pids[i],p,sizeof(p))>0 && strstr(p,"RustClient")){pid=pids[i];break;}
    }
    if(pid<0){printf("[!] No Rust\n");return 1;}
    if(task_for_pid(mach_task_self(),pid,&g_task)!=0){printf("[!] t_f_p\n");return 1;}

    const uint64_t VTABLE=0x1279db300;
    const int SID_OFF=0x630, PM_OFF=0x530;
    const uint64_t SID_MIN=76561198000000000ULL, SID_MAX=76561200000000000ULL;

    struct Rg { uint64_t s,e; };
    static Rg regs[128000]; int rc=0;
    mach_vm_address_t a=0; mach_vm_size_t sz; vm_region_basic_info_data_64_t info; mach_msg_type_number_t cnt; mach_port_t obj;
    while(rc<128000){
        cnt=VM_REGION_BASIC_INFO_COUNT_64;
        if(mach_vm_region(g_task,&a,&sz,VM_REGION_BASIC_INFO_64,(vm_region_info_t)&info,&cnt,&obj))break;
        if((info.protection&1)&&(info.protection&2)&&sz<=256*1024*1024)regs[rc++]={a,a+sz};
        a+=sz;
    }
    if(rc==0){printf("[!] No regions\n");return 1;}

    static uint8_t buf[8*1024*1024];
    struct Player { uint64_t sid,pm; int n; };
    Player players[64]; int pc=0;

    for(int ri=0;ri<rc&&pc<60;ri++){
        for(uint64_t off=0;off<regs[ri].e-regs[ri].s;off+=8*1024*1024){
            uint64_t ch=regs[ri].e-regs[ri].s-off; if(ch>8*1024*1024)ch=8*1024*1024;
            mach_vm_size_t got=0;
            if(mach_vm_read_overwrite(g_task,regs[ri].s+off,ch,(vm_address_t)buf,&got))break;
            for(size_t i=0;i+8<=got;i+=8){
                uint64_t v; memcpy(&v,buf+i,8);
                if(v!=VTABLE)continue;
                uint64_t bp=regs[ri].s+off+i;
                uint64_t sid=r64(bp+SID_OFF);
                if(sid<SID_MIN||sid>=SID_MAX)continue;
                uint64_t pm=r64(bp+PM_OFF);
                if(!vptr(pm))continue;
                int dup=0;
                for(int j=0;j<pc;j++)if(players[j].sid==sid){dup=1;break;}
                if(dup)continue;
                players[pc++]={sid,pm,0};
            }
        }
    }

    printf("[+] %d players\n",pc);
    if(pc==0){printf("[!] No players found\n");return 1;}

    // Scan for Vec3 positions
    printf("\n=== Potential Vec3 positions (>=5 players with valid xyz) ===\n");
    for(int bo=0;bo<0x3f8;bo+=4){
        int valid=0;
        for(int i=0;i<pc;i++){
            float vx=rf(players[i].pm+bo);
            float vy=rf(players[i].pm+bo+4);
            float vz=rf(players[i].pm+bo+8);
            if(isfinite(vx)&&isfinite(vy)&&isfinite(vz)&&
               vx>-5000&&vx<5000&&vz>-5000&&vz<5000&&vy>-200&&vy<2000&&
               (vx!=0||vz!=0)){
                valid++;
            }
        }
        if(valid>=5){
            printf("  PM+0x%03x: %d players\n",bo,valid);
            for(int i=0;i<3&&i<pc;i++){
                float vx=rf(players[i].pm+bo);
                float vy=rf(players[i].pm+bo+4);
                float vz=rf(players[i].pm+bo+8);
                printf("    SID=%llu: (%.1f, %.1f, %.1f)\n",players[i].sid%100000,vx,vy,vz);
            }
        }
    }

    // Dump first PM fully
    printf("\n=== Full PM dump for SID=%llu (PM=0x%llx) ===\n",players[0].sid,players[0].pm);
    for(int bo=0;bo<0x300;bo+=16){
        printf("  +0x%03x: ",bo);
        for(int j=0;j<16;j+=4){
            float f=rf(players[0].pm+bo+j);
            uint32_t raw; memcpy(&raw,&f,4);
            if(isfinite(f)&&f!=0)printf("%.2f ",f);
            else printf("%08x ",raw);
        }
        printf("\n");
    }

    return 0;
}