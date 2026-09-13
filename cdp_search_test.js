// cdp_search_test.js — cas POSITIF de la recherche : on prend un vrai shortname du flux live
const http = require('http'), fs = require('fs');
const get = u => new Promise((res, rej) => { http.get(u, r => { let d = ''; r.on('data', c => d += c); r.on('end', () => res(JSON.parse(d))); }).on('error', rej); });
const sleep = ms => new Promise(r => setTimeout(r, ms));
(async () => {
  const live = JSON.parse(fs.readFileSync('/tmp/rr02_radar.json', 'utf8'));
  const names = (live.items || []).map(i => i.n).filter(Boolean);
  const freq = {}; names.forEach(n => freq[n] = (freq[n] || 0) + 1);
  const top = Object.entries(freq).sort((a, b) => b[1] - a[1]).slice(0, 6);
  console.log('items live :', names.length, '| top shortnames :', JSON.stringify(top));

  const list = await get('http://127.0.0.1:9333/json/list');
  const t = list.find(x => x.type === 'page');
  const ws = new WebSocket(t.webSocketDebuggerUrl);
  let id = 0; const pend = {};
  const send = (m, p = {}) => new Promise(r => { const i = ++id; pend[i] = r; ws.send(JSON.stringify({ id: i, method: m, params: p })); });
  ws.onmessage = e => { const m = JSON.parse(e.data); if (m.id && pend[m.id]) { pend[m.id](m.result); delete pend[m.id]; } };
  await new Promise(r => ws.onopen = r);
  await send('Page.enable'); await send('Runtime.enable');
  await send('Page.navigate', { url: 'http://127.0.0.1:8789/' });
  await sleep(3500);
  const ev = async expr => { const r = await send('Runtime.evaluate', { expression: expr, returnByValue: true }); return r.result && r.result.value; };

  for (const [nm] of top.slice(0, 3)) {
    const q = nm.split('.')[0].slice(0, 6);
    await ev(`(function(){const e=document.getElementById('f_q');e.value=${JSON.stringify(q)};e.dispatchEvent(new Event('input'));return 1;})()`);
    await sleep(600);
    const res = await ev(`(function(){const iv=itemsVisibles(autoMe||anchor);return JSON.stringify({q:S.q,retenus:iv.list.length,total:iv.total,masques:iv.hid,ex:iv.list.slice(0,3).map(i=>i.n)});})()`);
    console.log('recherche "%s"'.padEnd(18), '->', res);
    console.log('   HUD             ->', await ev("document.getElementById('ith').textContent"));
  }
  await ev("(function(){const e=document.getElementById('f_q');e.value='';e.dispatchEvent(new Event('input'));return 1;})()");
  await ev("(function(){localStorage.removeItem('rr02.gui');return 1;})()");
  await sleep(300);
  const shot = await send('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync('/tmp/gui_panel.png', Buffer.from(shot.data, 'base64'));
  console.log('screenshot -> /tmp/gui_panel.png');
  process.exit(0);
})();
