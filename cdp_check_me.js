// cdp_check_me.js — état JS réel de l'overlay (auto-suivi MOI)
const http = require('http');
const get = u => new Promise((res, rej) => { http.get(u, r => { let d = ''; r.on('data', c => d += c); r.on('end', () => res(JSON.parse(d))); }).on('error', rej); });
const sleep = ms => new Promise(r => setTimeout(r, ms));

(async () => {
  const list = await get('http://127.0.0.1:9333/json/list');
  const t = list.find(x => x.type === 'page');
  const ws = new WebSocket(t.webSocketDebuggerUrl);
  let id = 0; const pend = {};
  const send = (m, p = {}) => new Promise(r => { const i = ++id; pend[i] = r; ws.send(JSON.stringify({ id: i, method: m, params: p })); });
  ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && pend[m.id]) { pend[m.id](m.result); delete pend[m.id]; } };
  await new Promise(r => ws.onopen = r);
  await send('Page.enable'); await send('Runtime.enable');
  await send('Page.navigate', { url: 'http://127.0.0.1:8789/' });
  await sleep(4500);
  const ev = async expr => {
    const r = await send('Runtime.evaluate', { expression: expr, returnByValue: true });
    return r.result && r.result.value;
  };
  const state = await ev(`JSON.stringify({
    age: document.getElementById('age').textContent,
    me_txt: document.getElementById('me').textContent,
    n: document.getElementById('n').textContent,
    fetch_me: (typeof data!=='undefined' && data.me) ? data.me : null,
    fetch_cam: (typeof data!=='undefined' && data.cam) ? data.cam : null,
    autoMe: (typeof autoMe!=='undefined') ? autoMe : 'undef',
    followMe: (typeof followMe!=='undefined') ? followMe : 'undef',
    cam: (typeof cam!=='undefined') ? cam : 'undef',
    scale: (typeof scale!=='undefined') ? scale : 'undef',
    rot: (typeof rot!=='undefined') ? rot : 'undef',
    hdgSrc: (typeof hdgSrc!=='undefined') ? hdgSrc : 'undef',
    keys: Object.keys((typeof data!=='undefined'&&data)||{}).join(',')
  })`);
  console.log(state);
  const shot = await send('Page.captureScreenshot', { format: 'png' });
  require('fs').writeFileSync('/tmp/me_cdp.png', Buffer.from(shot.data, 'base64'));
  console.log('screenshot -> /tmp/me_cdp.png');
  process.exit(0);
})();
