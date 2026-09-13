// Test E2E du clic sur un point : CDP -> Runtime.evaluate + Input.dispatchMouseEvent
// usage: node cdp_click_test.js <wsUrl>
const wsUrl = process.argv[2];
const ws = new WebSocket(wsUrl);
let id = 0; const pend = new Map();
function send(method, params = {}) {
  return new Promise((res, rej) => { const i = ++id; pend.set(i, { res, rej });
    ws.send(JSON.stringify({ id: i, method, params })); });
}
ws.onmessage = (e) => { const m = JSON.parse(e.data);
  if (m.id && pend.has(m.id)) { const p = pend.get(m.id); pend.delete(m.id);
    m.error ? p.rej(new Error(JSON.stringify(m.error))) : p.res(m.result); } };
ws.onopen = async () => {
  try {
    const evalJs = async (expr) => {
      const r = await send('Runtime.evaluate', { expression: expr, returnByValue: true, awaitPromise: true });
      if (r.exceptionDetails) throw new Error(JSON.stringify(r.exceptionDetails));
      return r.result.value;
    };
    const before = await evalJs(`location.href`);
    const target = await evalJs(`(()=>{const P=data.players||[];const on=P.filter(p=>p.on);
      const p=on[0]||P[0]; const sx=(p.x-cam.x)*scale+innerWidth/2, sy=(p.z-cam.z)*scale+innerHeight/2;
      return JSON.stringify({id:p.id,x:p.x,z:p.z,sx,sy,idx:P.indexOf(p),hud:document.getElementById('me').textContent});})()`);
    const t = JSON.parse(target);
    console.log('AVANT  hud =', t.hud);
    console.log('cible  = id', t.id, 'index', t.idx, 'monde', t.x, t.z, '-> ecran', Math.round(t.sx), Math.round(t.sy));
    const common = { x: t.sx, y: t.sy, button: 'left', clickCount: 1, buttons: 1 };
    await send('Input.dispatchMouseEvent', { type: 'mousePressed', ...common });
    await send('Input.dispatchMouseEvent', { type: 'mouseReleased', ...common });
    await new Promise(r => setTimeout(r, 2500));
    const after = JSON.parse(await evalJs(`JSON.stringify({hud:document.getElementById('me').textContent,
      near:document.getElementById('an').textContent, hash:location.hash,
      cam:[+cam.x.toFixed(1),+cam.z.toFixed(1)]})`));
    console.log('APRES  hud =', after.hud);
    console.log('       cible proche =', after.near, '| hash', after.hash);
    console.log('       cam =', after.cam, '(attendu si suivi =', [t.x, t.z], ')');
    const camOk = Math.abs(after.cam[0] - t.x) < 1.5 && Math.abs(after.cam[1] - t.z) < 1.5;
    const hudOk = after.hud.includes(String(t.id));
    console.log(camOk && hudOk ? 'RESULTAT: OK — clic pris en compte, camera centree sur la cible'
                              : 'RESULTAT: ECHEC — ' + JSON.stringify({ camOk, hudOk }));
    process.exit(camOk && hudOk ? 0 : 1);
  } catch (e) { console.error('ERREUR', e.message); process.exit(2); }
};
ws.onerror = (e) => { console.error('WS error', e.message || e); process.exit(3); };
