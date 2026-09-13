// Test E2E des gestes : ancre (clic vide) + liberation (double-clic) + zoom molette
const wsUrl = process.argv[2];
const ws = new WebSocket(wsUrl);
let id = 0; const pend = new Map();
function send(m, p = {}) { return new Promise((res, rej) => { const i = ++id; pend.set(i, { res, rej }); ws.send(JSON.stringify({ id: i, method: m, params: p })); }); }
ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && pend.has(m.id)) { const p = pend.get(m.id); pend.delete(m.id); m.error ? p.rej(new Error(JSON.stringify(m.error))) : p.res(m.result); } };
const sleep = ms => new Promise(r => setTimeout(r, ms));
ws.onopen = async () => {
  try {
    const ev = async expr => { const r = await send('Runtime.evaluate', { expression: expr, returnByValue: true }); if (r.exceptionDetails) throw new Error(JSON.stringify(r.exceptionDetails)); return r.result.value; };
    const click = async (x, y, n = 1) => {
      const c = { x, y, button: 'left', clickCount: n, buttons: 1 };
      await send('Input.dispatchMouseEvent', { type: 'mousePressed', ...c });
      await send('Input.dispatchMouseEvent', { type: 'mouseReleased', ...c });
      await sleep(700);
    };
    // point d'ecran le plus eloigne de tout point joueur, et hors panneaux UI
    const spot = JSON.parse(await ev(`(()=>{const P=data.players||[];
      const scr=P.map(p=>[(p.x-cam.x)*scale+innerWidth/2,(p.z-cam.z)*scale+innerHeight/2]);
      let best=null;
      for(let y=140;y<innerHeight-140;y+=20) for(let x=420;x<innerWidth-260;x+=20){
        let m=1e9; for(const s of scr){const d=Math.hypot(s[0]-x,s[1]-y); if(d<m)m=d;}
        if(!best||m>best.m) best={x,y,m};}
      return JSON.stringify(best);})()`));
    console.log('vide choisi:', JSON.stringify(spot));
    const res = { spot };
    // A) clic dans le vide -> ancre
    await click(spot.x, spot.y);
    res.ancre = JSON.parse(await ev(`JSON.stringify({anchor:anchor&&[+anchor.x.toFixed(1),+anchor.z.toFixed(1)],focusId,
      hudAn:document.getElementById('an').textContent})`));
    // B) double-clic au meme endroit -> liberation suivi + ancre
    await click(spot.x, spot.y, 2);
    await sleep(1500);
    res.double = JSON.parse(await ev(`JSON.stringify({focusId,anchor,hudMe:document.getElementById('me').textContent,hash:location.hash})`));
    // C) molette -> zoom avant
    const z0 = await ev(`scale`);
    await send('Input.dispatchMouseEvent', { type: 'mouseWheel', x: 700, y: 400, deltaX: 0, deltaY: -120 });
    await sleep(400);
    const z1 = await ev(`scale`);
    res.zoom = { avant: +z0.toFixed(2), apres: +z1.toFixed(2), zoomAvantOK: z1 > z0 };
    console.log(JSON.stringify(res, null, 1));
    const ok = res.ancre.anchor !== null && res.double.focusId === null && res.double.anchor === null && res.zoom.zoomAvantOK;
    console.log(ok ? 'RESULTAT: OK — ancre posee, double-clic libere tout, molette zoome'
                   : 'RESULTAT: A VERIFIER');
    process.exit(0);
  } catch (e) { console.error('ERREUR', e.message); process.exit(2); }
};
ws.onerror = e => { console.error('WS error', e.message || e); process.exit(3); };
