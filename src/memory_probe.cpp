// Bounded read-only Mach/dyld diagnostic. No injection or game-memory writes.
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach-o/loader.h>
#include <libproc.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>
#include <sstream>
#include <iostream>
#include <algorithm>
static task_t task=MACH_PORT_NULL;
static uint64_t base=0,slide=0;
static bool rd(uint64_t a,void*b,size_t n){mach_vm_size_t got=0;auto k=mach_vm_read_overwrite(task,a,n,(mach_vm_address_t)b,&got);if(k||got!=n){fprintf(stderr,"READ_FAIL address=0x%llx size=%zu kr=%d got=%llu\n",(unsigned long long)a,n,k,(unsigned long long)got);return false;}return true;}
static std::string str(uint64_t a){std::string s;for(int i=0;i<512;i++){char c=0;if(!rd(a+i,&c,1))return "<unreadable>";if(!c)return s;s+=c;}return s;}
struct Images{uint32_t version,count;uint64_t array;};
struct Image{uint64_t load,path,date;};
int main(){
 setbuf(stdout,nullptr); int bytes=proc_listpids(PROC_ALL_PIDS,0,nullptr,0); if(bytes<=0)return 1;
 std::vector<pid_t> pids(bytes/sizeof(pid_t)+256); bytes=proc_listpids(PROC_ALL_PIDS,0,pids.data(),int(pids.size()*sizeof(pid_t)));
 pid_t pid=0;for(int i=0;i<bytes/int(sizeof(pid_t));i++){char p[PROC_PIDPATHINFO_MAXSIZE]={};if(proc_pidpath(pids[i],p,sizeof p)>0&&strstr(p,"/RustClient.app/Contents/MacOS/Rust")){pid=pids[i];break;}}
 if(!pid){puts("NO_RUST_PROCESS");return 1;}auto kr=task_for_pid(mach_task_self(),pid,&task);printf("PID=%d task_for_pid=%d\n",pid,kr);if(kr)return 2;
 task_dyld_info_data_t d={};mach_msg_type_number_t cnt=TASK_DYLD_INFO_COUNT;kr=task_info(task,TASK_DYLD_INFO,(task_info_t)&d,&cnt);if(kr)return 3;
 Images im={};if(!rd(d.all_image_info_addr,&im,sizeof im)||im.count>10000||!im.count)return 4;
 std::vector<Image> ims(im.count);if(!rd(im.array,ims.data(),ims.size()*sizeof(Image)))return 5;
 for(auto i:ims){auto p=str(i.path);if(p.find("/GameAssembly.dylib")!=std::string::npos){base=i.load;break;}}
 if(!base){puts("NO_GAMEASSEMBLY");return 6;}
 mach_header_64 h={};if(!rd(base,&h,sizeof h)||h.magic!=MH_MAGIC_64||h.sizeofcmds>1048576)return 7;
 std::vector<uint8_t> cmds(h.sizeofcmds);if(!rd(base+sizeof h,cmds.data(),cmds.size()))return 8;
 size_t off=0;bool text=false;for(uint32_t j=0;j<h.ncmds;j++){if(off+sizeof(load_command)>cmds.size())return 9;load_command lc;memcpy(&lc,cmds.data()+off,sizeof lc);if(lc.cmdsize<sizeof lc||off+lc.cmdsize>cmds.size())return 9;if(lc.cmd==LC_SEGMENT_64&&lc.cmdsize>=sizeof(segment_command_64)){segment_command_64 sg;memcpy(&sg,cmds.data()+off,sizeof sg);if(!strncmp(sg.segname,"__TEXT",16)&&sg.fileoff==0){slide=base-sg.vmaddr;text=true;}}off+=lc.cmdsize;}
 if(!text)return 10;
 printf("BASE=0x%llx SLIDE=0x%llx IMAGES=%u\n",(unsigned long long)base,(unsigned long long)slide,im.count);
 puts("Commands: r <imageVA-hex> <size-hex>; a <absolute-hex> <size-hex>; c <class-hex>; q");
 std::string line;while(std::getline(std::cin,line)){std::istringstream ss(line);char op;uint64_t a=0,n=0;ss>>op;if(op=='q')break;ss>>std::hex>>a>>n;if(op=='c'){uint64_t name=0,parent=0,sf=0;bool ok=rd(a+0x10,&name,8)&&rd(a+0x58,&parent,8)&&rd(a+0xb8,&sf,8);if(ok)printf("CLASS 0x%llx name=%s parent=0x%llx sf=0x%llx\n",(unsigned long long)a,str(name).c_str(),(unsigned long long)parent,(unsigned long long)sf);continue;}if(op!='r'&&op!='a')continue;if(n==0||n>0x10000){puts("BAD_SIZE");continue;}if(op=='r')a+=slide;std::vector<unsigned char>b(n);if(!rd(a,b.data(),n))continue;for(size_t i=0;i<n;i+=16){printf("%016llx:",(unsigned long long)(a+i));for(size_t j=i;j<std::min<size_t>(i+16,n);j++)printf(" %02x",b[j]);puts("");}puts("DONE");}
 mach_port_deallocate(mach_task_self(),task);return 0;
}
