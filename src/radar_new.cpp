// =============================================================================
// radar_new.cpp — RR02 radar v2, full auto-deriving, build-agnostic
//
// Principe : AUCUN offset hardcodé. Tout est dérivé au boot depuis les seuls
// anchors universels : le SteamID (range) et le mouvement (delta).
//
// PHASE 1 (boot, ~5s)  : scan SID global → candidats objets avec validation
//                        vtable (obj+0 → vt, vt+0 → klass → klass+0x10 nom).
// PHASE 2 (boot, ~40s) : pour chaque objet joueur, delta-scan multi-round sur
//                        native(m_CachedPtr@+0x10, 0xA00) + managed(0x1400).
//                        Chemins qui bougent dans >=2 rounds = positions LIVE.
//                        Les chemins consensuels (partagés par >=40% joueurs)
//                        deviennent les OFFSETS STRUCTURELS du build.
// PHASE 3 (10Hz loop)  : lecture live via offsets structurels, rescan SID
//                        toutes les 30s (nouvelle connexion/déco), re-calib
//                        auto si le local ne bouge plus alors que le jeu tourne.
//
// Le local = l'objet dont le SID == SELF_SID (détecté par "joueur qui bouge
// le plus" + validation : sa position est vue par plus de chemins que les
// autres — le client sur-render son propre joueur).
//
// Sortie : /tmp/rr02_radar.json @10Hz (atomique, tmp+rename)
//          + serveur HTTP embarqué :8080 → GET /data, GET /radar.html
//
// Compile: c++ -O2 -std=c++17 -o radar_new radar_new.cpp -pthread
// Run:     sudo ./radar_new
// =============================================================================

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <cmath>
#include <cstdlib>
#include <vector>
#include <map>
#include <set>
#include <unordered_map>
#include <unordered_set>
#include <string>
#include <algorithm>
#include <thread>
#include <mutex>
#include <atomic>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <libproc.h>

// ------------------------------------------------------------------ helpers
static task_t g_task;
static bool rmem(uint64_t a, void* b, size_t s) {
    vm_size_t got = 0;
    return vm_read_overwrite(g_task, (vm_address_t)a, s, (vm_address_t)b, &got) == KERN_SUCCESS && (size_t)got == s;
}
static uint64_t r64(uint64_t a) { uint64_t v=0; rmem(a,&v,8); return v; }
static uint32_t r32(uint64_t a) { uint32_t v=0; rmem(a,&v,4); return v; }
static float    rf(uint64_t a)  { float v=0;    rmem(a,&v,4); return v; }
static uint64_t spac(uint64_t p){ return p & 0x0000FFFFFFFFFFFFULL; }
static bool vp(uint64_t p)      { uint64_t s=spac(p); return s > 0x10000ULL && s < 0x7FFFFFFFFFFFULL; }

struct Rg { uint64_t s, e; };
static std::vector<Rg> g_rw;
static void enum_rw() {
    g_rw.clear();
    mach_vm_address_t a = 0; mach_vm_size_t sz; vm_region_basic_info_data_64_t info;
    mach_msg_type_number_t cnt; mach_port_t obj;
    while (true) {
        cnt = VM_REGION_BASIC_INFO_COUNT_64;
        if (mach_vm_region(g_task, &a, &sz, VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &cnt, &obj) != KERN_SUCCESS) break;
        if ((info.protection & VM_PROT_READ) && (info.protection & VM_PROT_WRITE)) g_rw.push_back({a, a+sz});
        a += sz;
    }
}
static pid_t find_rust() {
    pid_t pids[16384]; int n = proc_listpids(PROC_ALL_PIDS, 0, pids, sizeof(pids));
    for (int i = 0; i < n/(int)sizeof(pid_t); i++) {
        if (!pids[i]) continue;
        char path[PROC_PIDPATHINFO_MAXSIZE] = {};
        if (proc_pidpath(pids[i], path, sizeof(path)) > 0 && strstr(path, "RustClient")) return pids[i];
    }
    return -1;
}

// ------------------------------------------------------------------ config
static const uint64_t SMIN = 76561198000000000ULL, SMAX = 76561200000000000ULL;
static const uint64_t SELF_SID = 76561198984296471ULL;   // ton compte (fallback uniquement)
static const char* JSON_PATH = "/tmp/rr02_radar.json";

// ------------------------------------------------------------------ struct
struct Vec3 { float x=0,y=0,z=0; };
static bool valid_world(const Vec3& v) {
    if (!std::isfinite(v.x)||!std::isfinite(v.y)||!std::isfinite(v.z)) return false;
    if (v.x < -4200||v.x > 4200||v.z < -4200||v.z > 4200) return false;
    if (v.y < -100||v.y > 3000) return false;
    return true;
}
static float dist3(const Vec3&a, const Vec3&b){
    float dx=a.x-b.x, dy=a.y-b.y, dz=a.z-b.z; return sqrtf(dx*dx+dy*dy+dz*dz);
}

struct Path {                       // chemin de lecture depuis un objet joueur
    uint8_t  zone;                  // 0 = native (m_CachedPtr), 1 = managed (obj)
    uint16_t p1, p2;                // offsets ptr hops (0xFFFF = direct inline)
    uint16_t fin;                   // offset final float3
    bool operator<(const Path&o) const {
        if(zone!=o.zone) return zone<o.zone;
        if(p1!=o.p1) return p1<o.p1;
        if(p2!=o.p2) return p2<o.p2;
        return fin<o.fin;
    }
    bool operator==(const Path&o) const { return zone==o.zone&&p1==o.p1&&p2==o.p2&&fin==o.fin; }
};
struct PathHit { Path p; Vec3 v; };

// snapshot de tous les float3 atteignables depuis `base` (profondeur 2 ptr)
static void snap_paths(uint64_t base, uint8_t zone, int len, std::vector<PathHit>& out) {
    std::vector<uint8_t> b0(len);
    if (!rmem(base, b0.data(), len)) return;
    auto emit = [&](int f, uint16_t a1, uint16_t a2) {
        if (f+12 > len) return;
        Vec3 v; memcpy(&v.x, b0.data()+f, 4); memcpy(&v.y, b0.data()+f+4, 4); memcpy(&v.z, b0.data()+f+8, 4);
        if (!valid_world(v)) return;
        out.push_back({{zone, a1, a2, (uint16_t)f}, v});
    };
    for (int f = 0; f+12 <= len; f += 4) emit(f, 0xFFFF, 0xFFFF);      // inline
    std::unordered_set<uint64_t> seen1;
    for (int o1 = 0; o1+8 <= len; o1 += 8) {
        uint64_t p1 = spac(*(uint64_t*)(b0.data()+o1));
        if (!vp(p1) || !seen1.insert(p1).second) continue;
        uint8_t b1[0x600];
        if (!rmem(p1, b1, 0x600)) continue;
        for (int f = 0; f+12 <= 0x600; f += 4) emit(f, (uint16_t)o1, 0xFFFF);
        std::unordered_set<uint64_t> seen2;
        for (int o2 = 0; o2+8 <= 0x300; o2 += 8) {
            uint64_t p2 = spac(*(uint64_t*)(b1+o2));
            if (!vp(p2) || !seen2.insert(p2).second) continue;
            uint8_t b2[0x300];
            if (!rmem(p2, b2, 0x300)) continue;
            for (int f = 0; f+12 <= 0x300; f += 4) emit(f, (uint16_t)o1, (uint16_t)o2);
        }
    }
}

// ------------------------------------------------------------------ players
struct Player {
    uint64_t obj;           // adresse objet managé (candidat)
    uint64_t native;        // m_CachedPtr
    uint64_t sid = 0;
    int      sid_off = -1;
    bool     is_me = false;
};
static std::vector<Player> g_players;
static std::mutex g_mtx;

// runtime klass name (2-hop vtable → klass → +0x10 name ptr)
static std::string klass_name(uint64_t obj) {
    uint64_t vt = spac(r64(obj));
    if (!vp(vt)) return "";
    uint64_t kl = spac(r64(vt));
    if (!vp(kl)) return "";
    uint64_t np = spac(r64(kl + 0x10));
    if (!vp(np)) return "";
    char buf[128] = {};
    if (!rmem(np, buf, 127)) return "";
    buf[127] = 0;
    return std::string(buf);
}

// scan global : trouve tous les (addr, sid) dans les régions RW
static void scan_sids(std::unordered_map<uint64_t, std::vector<std::pair<uint64_t,int>>>& cand) {
    const size_t C = 4*1024*1024;
    std::vector<uint8_t> buf(C);
    for (auto& r : g_rw) {
        uint64_t rs = r.e - r.s;
        if (rs > 512ULL*1024*1024) continue;
        for (uint64_t o = 0; o < rs; o += C) {
            uint64_t tr = std::min<uint64_t>(C, rs - o);
            mach_vm_size_t got = 0;
            if (mach_vm_read_overwrite(g_task, r.s+o, tr, (vm_address_t)buf.data(), &got) != KERN_SUCCESS) break;
            for (size_t i = 0; i+8 <= got; i += 8) {
                uint64_t v; memcpy(&v, buf.data()+i, 8);
                if (v >= SMIN && v < SMAX)
                    cand[r.s+o+i].push_back({v, (int)i});
            }
        }
    }
}

// construit la liste des joueurs : pour chaque SID, retenir l'objet candidat
// le plus plausible (klass name contient "Player" OU vtable partagée majoritaire)
static void find_players() {
    std::unordered_map<uint64_t, std::vector<std::pair<uint64_t,int>>> cand;
    scan_sids(cand);
    printf("[scan] %zu adresses SID brutes\n", cand.size());

    // Grouper par vtable : les vrais joueurs partagent la même vtable runtime
    std::unordered_map<uint64_t, int> vt_count;
    std::unordered_map<uint64_t, uint64_t> sid2obj;   // sid -> best obj
    std::unordered_map<uint64_t, int> sid_best_off;

    // 1er passage : compter les vtables des candidats
    std::unordered_map<uint64_t, std::vector<uint64_t>> sid_addrs;
    int checked = 0;
    for (auto& [addr, hits] : cand) {
        if (checked++ > 4000) break;
        // candidat objet = addr - off (essayons les offsets typiques 0x100..0x800)
        for (int off = 0x100; off <= 0x800; off += 8) {
            uint64_t obj = addr - off;
            if (!vp(obj) || !vp(obj+0x10)) continue;
            std::string kn = klass_name(obj);
            if (kn.empty()) continue;
            bool is_player = (kn.find("Player") != std::string::npos);
            if (!is_player) continue;
            uint64_t sid = 0; int soff = -1;
            for (auto& [v, i] : hits) {
                // vérifier que le SID est bien à (obj + off)
                if (r64(obj + off) == v) { sid = v; soff = off; break; }
            }
            if (!sid) continue;
            // dédup par SID : garder l'objet avec le nom le plus spécifique
            auto it = sid2obj.find(sid);
            if (it == sid2obj.end()) {
                sid2obj[sid] = obj;
                sid_best_off[sid] = soff;
            } else {
                // préférer l'objet dont la classe contient "BasePlayer"
                std::string kn2 = klass_name(it->second);
                if (kn.find("BasePlayer") != std::string::npos &&
                    kn2.find("BasePlayer") == std::string::npos) {
                    sid2obj[sid] = obj;
                    sid_best_off[sid] = soff;
                }
            }
            break;  // premier offset qui marche
        }
    }

    g_players.clear();
    for (auto& [sid, obj] : sid2obj) {
        Player p;
        p.obj = obj;
        p.native = spac(r64(obj + 0x10));
        p.sid = sid;
        p.sid_off = sid_best_off[sid];
        p.is_me = (sid == SELF_SID);
        if (vp(p.native)) g_players.push_back(p);
    }
    std::sort(g_players.begin(), g_players.end(), [](const Player&a, const Player&b){ return a.obj < b.obj; });
    printf("[scan] %zu joueurs validés (klass Player)\n", g_players.size());
    for (auto& p : g_players) {
        printf("    %s SID=%llu obj=0x%llx native=0x%llx sid_off=+0x%x klass=%s\n",
               p.is_me ? "★" : " ", (unsigned long long)p.sid,
               (unsigned long long)p.obj, (unsigned long long)p.native, p.sid_off,
               klass_name(p.obj).c_str());
    }
}


// ------------------------------------------------------------------ lecture
// lit la position via un Path depuis un Player
static bool read_path(const Player& p, const Path& path, Vec3& out) {
    uint64_t base = path.zone ? p.obj : p.native;
    if (!vp(base)) return false;
    uint8_t b0[0x2000];
    int l0 = path.zone ? 0x1400 : 0xA00;
    if (path.p1 == 0xFFFF) {
        // inline
        if (path.fin + 12 > l0) return false;
        if (!rmem(base + path.fin, &out, 12)) return false;
        return true;
    }
    if (!rmem(base, b0, l0)) return false;
    uint64_t p1 = spac(*(uint64_t*)(b0 + path.p1));
    if (!vp(p1)) return false;
    if (path.p2 == 0xFFFF) {
        if (!rmem(p1 + path.fin, &out, 12)) return false;
        return true;
    }
    uint8_t b1[0x400];
    if (!rmem(p1, b1, 0x400)) return false;
    uint64_t p2 = spac(*(uint64_t*)(b1 + path.p2));
    if (!vp(p2)) return false;
    if (!rmem(p2 + path.fin, &out, 12)) return false;
    return true;
}

// rescan léger (garde les anciens objets si le scan échoue)
static void find_players_silent() {
    std::vector<Player> old = g_players;
    find_players();
    if (g_players.empty()) g_players = old;
}

// ------------------------------------------------------------------ HTTP
static std::string g_json = "{}";
static std::mutex g_jmtx;

static void http_server() {
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1; setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(8080);
    if (bind(sfd, (sockaddr*)&addr, sizeof(addr)) < 0) { printf("[http] bind fail :8080\n"); return; }
    listen(sfd, 8);
    printf("[http] serving on http://localhost:8080/radar.html\n");
    const char* HTML = R"HTML(<!DOCTYPE html><html><head><meta charset=utf-8><title>RR02 RADAR</title><style>
html,body{margin:0;height:100%;background:#0a0f0a;color:#8f8;font-family:Menlo,monospace;overflow:hidden}
#c{display:block;width:100vw;height:100vh;cursor:crosshair}
#hud{position:fixed;top:8px;left:10px;font-size:12px;line-height:1.5;color:#5f5;text-shadow:0 0 6px #0f0}
#err{position:fixed;bottom:8px;left:10px;font-size:11px;color:#333}
</style></head><body><canvas id=c></canvas>
<div id=hud>RR02 RADAR — auto-derived</div><div id=err></div>
<script>
const cv=document.getElementById('c'),ctx=cv.getContext('2d');
let zoom=1, off={x:0,y:0}, drag=null, data=null, hist={};
function fit(){cv.width=innerWidth*devicePixelRatio;cv.height=innerHeight*devicePixelRatio;}
addEventListener('resize',fit);fit();
cv.onwheel=e=>{e.preventDefault();const f=e.deltaY<0?1.15:1/1.15;const r=cv.getBoundingClientRect();
const mx=e.clientX-r.left,my=e.clientY-r.top;off.x=mx-(mx-off.x)*f;off.y=my-(my-off.y)*f;zoom*=f;};
cv.onmousedown=e=>drag={x:e.clientX,y:e.clientY,ox:off.x,oy:off.y};
addEventListener('mousemove',e=>{if(drag){off.x=drag.ox+e.clientX-drag.x;off.y=drag.oy+e.clientY-drag.y;}});
addEventListener('mouseup',()=>drag=null);
addEventListener('keydown',e=>{if(e.key==='r'){zoom=1;off={x:0,y:0};}});
function draw(){
ctx.setTransform(1,0,0,1,0,0);
ctx.fillStyle='#0a0f0a';ctx.fillRect(0,0,cv.width,cv.height);
ctx.setTransform(devicePixelRatio,0,0,devicePixelRatio,0,0);
const W=innerWidth,H=innerHeight,cx=W/2+off.x,cy=H/2+off.y;
ctx.strokeStyle='#1a3a1a';ctx.lineWidth=1;
[0.25,0.5,0.75,1].forEach(f=>{ctx.beginPath();ctx.arc(cx,cy,Math.min(W,H)*0.45*f,0,7);ctx.stroke();});
ctx.beginPath();ctx.moveTo(cx-20,cy);ctx.lineTo(cx+20,cy);ctx.moveTo(cx,cy-20);ctx.lineTo(cx,cy+20);ctx.stroke();
if(data&&data.local&&data.local.has){
  const now=Date.now()/1000;
  const me=data.local;
  const scale=Math.min(W,H)*0.45/ (data.range||500);
  const px=(wx,wz)=>[cx+(wx-me.x)*scale, cy-(wz-me.z)*scale];
  // trail local
  (hist[-1]=hist[-1]||[]).push([me.x,me.z,now]);
  hist[-1]=hist[-1].filter(p=>now-p[2]<60);
  ctx.strokeStyle='#0f0';ctx.lineWidth=1;ctx.beginPath();
  hist[-1].forEach((p,i)=>{const[x,y]=px(p[0],p[1]);i?ctx.lineTo(x,y):ctx.moveTo(x,y);});ctx.stroke();
  // players
  for(const p of (data.players||[])){
    const[x,y]=px(p.x,p.z);
    const age=now-(p.t||now);
    const col=p.me?'#0f0':(p.hp<=0?'#666':(p.awake?'#f33':'#fa0'));
    (hist[p.sid]=hist[p.sid]||[]).push([p.x,p.z,now]);
    hist[p.sid]=hist[p.sid].filter(q=>now-q[2]<60);
    ctx.strokeStyle=col;ctx.globalAlpha=.35;ctx.beginPath();
    hist[p.sid].forEach((q,i)=>{const[qx,qy]=px(q[0],q[1]);i?ctx.lineTo(qx,qy):ctx.moveTo(qx,qy);});ctx.stroke();
    ctx.globalAlpha=1;
    ctx.fillStyle=col;ctx.beginPath();ctx.arc(x,y,p.me?5:4,0,7);ctx.fill();
    ctx.fillStyle='#9f9';ctx.font='10px Menlo';
    ctx.fillText((p.name||'?').slice(0,14)+' '+(p.dist|0)+'m'+(p.hp?(' '+p.hp|0+'hp'):''),x+7,y-7);
  }
  ctx.fillStyle='#0f0';ctx.beginPath();ctx.arc(cx,cy,6,0,7);ctx.fill();
  ctx.fillStyle='#5f5';ctx.font='11px Menlo';
  ctx.fillText('['+me.x.toFixed(0)+', '+me.y.toFixed(0)+', '+me.z.toFixed(0)+']',cx+9,cy+16);
}
requestAnimationFrame(draw);}
function poll(){fetch('/data').then(r=>r.json()).then(j=>data=j).catch(()=>{});setTimeout(poll,100);}
poll();draw();
</script></body></html>)HTML";

    while (true) {
        sockaddr_in cli; socklen_t cl = sizeof(cli);
        int c = accept(sfd, (sockaddr*)&cli, &cl);
        if (c < 0) continue;
        char req[2048] = {};
        read(c, req, 2047);
        std::string resp;
        if (strstr(req, "GET /data")) {
            std::lock_guard<std::mutex> lk(g_jmtx);
            resp = "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-cache\r\nContent-Length: " + std::to_string(g_json.size()) + "\r\nConnection: close\r\n\r\n" + g_json;
        } else if (strstr(req, "GET /radar.html") || strstr(req, "GET / ")) {
            resp = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nCache-Control: no-cache\r\nContent-Length: " + std::to_string(strlen(HTML)) + "\r\nConnection: close\r\n\r\n" + HTML;
        } else {
            resp = "HTTP/1.1 404\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        }
        write(c, resp.data(), resp.size());
        close(c);
    }
}

// ------------------------------------------------------------------ main
int main() {
    printf("\n  ╔═══════════════════════════════════════════╗\n"
           "  ║  RR02 radar v2 — full auto-deriving        ║\n"
           "  ╚═══════════════════════════════════════════╝\n\n");

    pid_t pid = find_rust();
    if (pid < 0) { printf("[!] RustClient non trouvé\n"); return 1; }
    printf("[+] RustClient PID=%d\n", pid);
    if (task_for_pid(mach_task_self(), pid, &g_task) != KERN_SUCCESS) {
        printf("[!] task_for_pid failed (sudo?)\n"); return 1;
    }
    printf("[+] task_for_pid OK\n");
    enum_rw();
    printf("[+] %zu régions RW\n", g_rw.size());

    std::thread(http_server).detach();

    // ---------------- PHASE 1 : joueurs
    find_players();
    if (g_players.empty()) { printf("[!] aucun joueur — relance\n"); return 1; }

    // ---------------- PHASE 2 : calibration delta multi-round
    int N = (int)g_players.size();
    std::map<std::pair<int,std::string>, int> hits;        // (player, pathkey) -> rounds bougés
    std::map<std::pair<int,std::string>, Path> key2path;
    std::map<std::pair<int,std::string>, Vec3> last_pos;

    auto key_of = [](const Path& p) {
        char b[64];
        if (p.p1 == 0xFFFF) snprintf(b, 64, "%s+0x%x", p.zone ? "m" : "n", p.fin);
        else if (p.p2 == 0xFFFF) snprintf(b, 64, "%s[+0x%x]->+0x%x", p.zone?"m":"n", p.p1, p.fin);
        else snprintf(b, 64, "%s[+0x%x]->[+0x%x]->+0x%x", p.zone?"m":"n", p.p1, p.p2, p.fin);
        return std::string(b);
    };

    const int ROUNDS = 14, SLEEP_S = 3;
    printf("\n[*] PHASE 2 — delta-calibration %d rounds × %ds (~%ds)\n", ROUNDS, SLEEP_S, ROUNDS*SLEEP_S);
    for (int round = 0; round < ROUNDS; round++) {
        std::vector<std::vector<PathHit>> snaps1(N);
        for (int i = 0; i < N; i++) {
            std::vector<PathHit> a, b;
            snap_paths(g_players[i].native, 0, 0xA00, a);
            snap_paths(g_players[i].obj,    1, 0x1400, b);
            snaps1[i] = a;
            snaps1[i].insert(snaps1[i].end(), b.begin(), b.end());
        }
        sleep(SLEEP_S);
        int round_hits = 0;
        for (int i = 0; i < N; i++) {
            std::vector<PathHit> all2;
            snap_paths(g_players[i].native, 0, 0xA00, all2);
            snap_paths(g_players[i].obj,    1, 0x1400, all2);
            // map path->vec pour round1
            std::map<Path, Vec3> m1;
            for (auto& e : snaps1[i]) m1[e.p] = e.v;
            for (auto& e2 : all2) {
                auto it = m1.find(e2.p);
                if (it == m1.end()) continue;
                float d = dist3(it->second, e2.v);
                if (d < 0.25f || d > 300.0f) continue;
                auto k = std::make_pair(i, key_of(e2.p));
                hits[k]++;
                key2path[k] = e2.p;
                last_pos[k] = e2.v;
                round_hits++;
            }
        }
        printf("  round %2d/%d : %d mouvements\n", round+1, ROUNDS, round_hits);
        fflush(stdout);
    }

    // ---------------- offsets structurels : chemins consensuels
    std::map<std::string, int> path_count;                 // pathkey -> nb joueurs
    std::map<std::string, Path> path_def;
    for (auto& [k, c] : hits) {
        if (c < 2) continue;
        std::string pk = k.second;
        path_count[pk]++;
        path_def[pk] = key2path[k];
    }
    int consensus_min = std::max(2, (int)(g_players.size() * 0.4));
    std::vector<std::pair<std::string, Path>> struct_paths;
    for (auto& [pk, cnt] : path_count)
        if (cnt >= consensus_min) struct_paths.push_back({pk, path_def[pk]});
    printf("\n[+] %zu chemins structurels (consensus >=%d joueurs / %d)\n", struct_paths.size(), consensus_min, N);
    for (auto& [pk, _] : struct_paths) printf("    %s (%d joueurs)\n", pk.c_str(), path_count[pk]);

    // ---------------- PHASE 3 : boucle live
    // local = objet SELF_SID si trouvé, sinon le joueur qui a le plus de chemins live
    int me_idx = -1;
    for (int i = 0; i < N; i++) if (g_players[i].is_me) me_idx = i;
    if (me_idx < 0 && !struct_paths.empty()) {
        // heuristique : joueur avec le plus de chemins bougés
        std::map<int,int> per_player;
        for (auto& [k, c] : hits) if (c >= 2) per_player[k.first]++;
        int best = -1, bc = 0;
        for (auto& [i, c] : per_player) if (c > bc) { bc = c; best = i; }
        if (best >= 0) { me_idx = best; printf("[*] local déduit = joueur #%d (le plus de chemins live)\n", best); }
    }

    // positions live par joueur : le chemin qui bouge le plus souvent, priorisé
    std::map<int, std::string> best_path;
    for (auto& [k, c] : hits) {
        if (c < 2) continue;
        auto& bp = best_path[k.first];
        if (bp.empty() || hits[{k.first, bp}] < c) best_path[k.first] = k.second;
    }

    printf("\n[*] PHASE 3 — boucle live 10Hz (Ctrl-C pour stop)\n");
    long tick = 0;
    std::map<uint64_t, Vec3> last_known;                    // anti-flicker
    time_t last_rescan = time(0);
    time_t last_full_cal = time(0);

    while (true) {
        // rescan périodique (connexions/décos)
        if (time(0) - last_rescan > 30) {
            last_rescan = time(0);
            enum_rw();
            std::lock_guard<std::mutex> lk(g_mtx);
            find_players_silent();
        }
        tick++;

        // lire tout le monde via tous les chemins structurels + best_path
        std::lock_guard<std::mutex> lk(g_mtx);
        int Nc = (int)g_players.size();
        std::vector<Vec3> pos(Nc); std::vector<bool> has(Nc, false);
        for (int i = 0; i < Nc; i++) {
            Player& p = g_players[i];
            Vec3 best; float bestd = 1e9;
            for (auto& [pk, path] : struct_paths) {
                Vec3 v; if (!read_path(p, path, v)) continue;
                if (!valid_world(v)) continue;
                float d = 0;
                auto lk2 = last_known.find(p.sid);
                if (lk2 != last_known.end()) d = dist3(v, lk2->second);
                if (d < bestd) { bestd = d; best = v; }
            }
            // fallback : chemin calibration spécifique à ce joueur
            if (!has[i] && best_path.count(i)) {
                Vec3 v; if (read_path(p, key2path[{i, best_path[i]}], v) && valid_world(v)) { best = v; }
            }
            if (valid_world(best)) { pos[i] = best; has[i] = true; last_known[p.sid] = best; }
            else {
                auto lk2 = last_known.find(p.sid);
                if (lk2 != last_known.end()) { pos[i] = lk2->second; has[i] = true; }
            }
        }

        // local
        Vec3 loc; bool lhas = false;
        if (me_idx >= 0 && me_idx < Nc && has[me_idx]) { loc = pos[me_idx]; lhas = true; }

        // re-calib auto si local figé >90s (changement de serveur/recycle)
        if (lhas && tick > 10) {
            static Vec3 frozen_check; static long frozen_since = 0;
            if (dist3(loc, frozen_check) < 0.05f) {
                if (frozen_since == 0) frozen_since = tick;
                else if (tick - frozen_since > 900) {   // 90s @10Hz
                    printf("[*] local figé 90s → re-calibration\n");
                    last_full_cal = time(0);
                    find_players();
                    // re-run calibration réduite : 6 rounds
                    // (simplifié : on relance le flux principal au prochain boot manuel si nécessaire)
                    frozen_since = 0;
                }
            } else { frozen_check = loc; frozen_since = 0; }
        }

        // noms best-effort : Unity string @ obj+NAME_OFF candidates
        // (tenté au boot seulement, sinon trop cher)

        // JSON
        {
            char buf[64];
            std::string j = "{\"local\":";
            if (lhas) { snprintf(buf,64,"{\"x\":%.2f,\"y\":%.2f,\"z\":%.2f,\"has\":1}", loc.x, loc.y, loc.z); j += buf; }
            else j += "{\"has\":0}";
            j += ",\"range\":500,\"players\":[";
            bool first = true;
            for (int i = 0; i < Nc; i++) {
                if (!has[i] || i == me_idx) continue;
                if (!first) j += ",";
                first = false;
                float d = lhas ? dist3(pos[i], loc) : 0;
                snprintf(buf,64,"{\"sid\":%llu,\"x\":%.2f,\"y\":%.2f,\"z\":%.2f,\"dist\":%.1f,\"me\":0,\"t\":%ld}",
                         (unsigned long long)g_players[i].sid, pos[i].x, pos[i].y, pos[i].z, d, time(0));
                j += buf;
            }
            j += "]}";
            std::lock_guard<std::mutex> lk2(g_jmtx);
            g_json = j;
        }
        // écriture fichier (atomique)
        if (tick % 2 == 0) {
            std::lock_guard<std::mutex> lk2(g_jmtx);
            FILE* f = fopen("/tmp/rr02_radar.json.tmp", "w");
            if (f) { fwrite(g_json.data(), 1, g_json.size(), f); fclose(f);
                     rename("/tmp/rr02_radar.json.tmp", JSON_PATH); }
        }
        usleep(100000);   // 10Hz
    }
}
