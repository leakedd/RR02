// Verification finale : recharge la page, verifie le nouveau HUD, refait le clic E2E, capture un screenshot
const fs = require('fs');
const wsUrl = process.argv[2], out = process.argv[3] || '/tmp/radar_hud.png';
const ws = new WebSocket(wsUrl);
let id = 0; const pend = new Map();
function send(m, p = {}) { return new Promise((res, rej) => { const i = ++id; pend.set(i, { res, rej }); ws.send(JSON.stringify({ id: i, method: m, params: p })); }); }
ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && pend.has(m.id)) { const p = pend.get(m.id); pend.delete(m.id); m.error ? p.rej(new Error(JSON.stringify(m.error))) : p.res(m.result); } };
const sleep = ms => new Promise(r => setTimeout(r, ms));
ws.onopen = async () => {
  try {
    const ev = async expr => { const r = await send('Runtime.evaluate', { expression: expr, returnByValue: true }); if (r.exceptionDetails) throw new Error(JSON.stringify(r.exceptionDetails)); return r.result.value; };
    await send('Page.reload', { ignoreCache: true });
    await sleep(5000);
    const before = JSON.parse(await ev(`JSON.stringify({hud:document.getElementById('me').textContent, mvl:document.getElementById('mvl').textContent, n:document.getElementById('n').textContent})`));
    console.log('HUD apres reload :', JSON.stringify(before));
    // clic E2E sur un point en ligne
    const t = JSON.parse(await ev(`(()=>{const P=data.players||[];const on=P.filter(p=>p.on);const p=on[0]||P[0];
      return JSON.stringify({id:p.id,x:p.x,z:p.z,sx:(p.x-cam.x)*scale+innerWidth/2,sy:(p.z-cam.z)*scale+innerHeight/2});})()`));
    const c = { x: t.sx, y: t.sy, button: 'left', clickCount: 1, buttons: 1 };
    await send('Input.dispatchMouseEvent', { type: 'mousePressed', ...c });
    await send('Input.dispatchMouseEvent', { type: 'mouseReleased', ...c });
    await sleep(2500);
    const after = JSON.parse(await ev(`JSON.stringify({hud:document.getElementById('me').textContent,near:document.getElementById('an').textContent,cam:[+cam.x.toFixed(1),+cam.z.toFixed(1)]})`));
    const ok = Math.abs(after.cam[0] - t.x) < 1.5 && Math.abs(after.cam[1] - t.z) < 1.5 && after.hud.includes(String(t.id));
    console.log('clic  -> cible id', t.id, '| hud:', after.hud, '| proche:', after.near);
    console.log('camera:', after.cam.join(', '), '| attendu:', t.x + ', ' + t.z, '=>', ok ? 'SUIVI OK' : 'ECHEC');
    const shot = await send('Page.captureScreenshot', { format: 'png' });
    fs.writeFileSync(out, Buffer.from(shot.data, 'base64'));
    console.log('screenshot:', out, fs.statSync(out).size, 'bytes');
    process.exit(ok ? 0 : 1);
  } catch (e) { console.error('ERREUR', e.message); process.exit(2); }
};
ws.onerror = e => { console.error('WS error', e.message || e); process.exit(3); };
