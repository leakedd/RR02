// cdp_gui_test.js — teste le panneau de réglages (filtres joueurs/items) dans un vrai Chrome
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
  await send('Page.addScriptToEvaluateOnNewDocument', {
    source: "window.__errs=[];addEventListener('error',e=>window.__errs.push(String(e.message||e.error)));window.__rej=[];addEventListener('unhandledrejection',e=>window.__rej.push(String(e.reason)));"
  });
  await send('Page.navigate', { url: 'http://127.0.0.1:8789/' });
  await sleep(4000);
  const ev = async expr => {
    const r = await send('Runtime.evaluate', { expression: expr, returnByValue: true });
    if (r.exceptionDetails) return 'EXCEPTION: ' + (r.exceptionDetails.exception && r.exceptionDetails.exception.description || r.exceptionDetails.text);
    return r.result && r.result.value;
  };
  const line = async (label, expr) => console.log(String(label).padEnd(30), '->', await ev(expr));

  await line('erreurs JS', "JSON.stringify({errs:(window.__errs||[]).slice(0,3),rej:(window.__rej||[]).slice(0,3)})");
  await line('panneau présent', "!!document.getElementById('f_sleep') && !!document.getElementById('f_q')");
  await line('reglages par défaut', "JSON.stringify(S)");
  await line('cpt items/joueurs', "JSON.stringify({vis:document.getElementById('vis').textContent,ith:document.getElementById('ith').textContent,sleep:document.getElementById('c_sleep').textContent})");

  const setChk = (idv, v) => `(function(){const e=document.getElementById('${idv}');e.checked=${v};e.dispatchEvent(new Event('change'));return true;})()`;
  const setTxt = (idv, v) => `(function(){const e=document.getElementById('${idv}');e.value=${JSON.stringify(v)};e.dispatchEvent(new Event('input'));return true;})()`;
  const setRng = (idv, v) => `(function(){const e=document.getElementById('${idv}');e.value=${v};e.dispatchEvent(new Event('input'));return true;})()`;

  console.log('\n--- FILTRE 1 : masquer les endormis ---');
  await ev(setChk('f_sleep', true)); await sleep(700);
  await line('S.hideSleep', 'S.hideSleep');
  await line('affichés / total', "document.getElementById('vis').textContent+' | '+(document.getElementById('n').textContent)");
  await line('compteur endormis masqués', "document.getElementById('c_sleep').textContent");
  await line('points dessinés (verts+gris)', "(function(){const P=data.players||[];let v=0,h=0;P.forEach((p,i)=>{if(playerVisible(p,i,focusedIndex(),autoMe||anchor))v++;else h++;});return v+' visibles / '+h+' masqués';})()");

  console.log('\n--- FILTRE 2 : catégorie médicale décochée ---');
  await ev(setChk('f_im', false)); await sleep(700);
  await line('S.cM', 'S.cM');
  await line('compteurs items', "JSON.stringify({tot:document.getElementById('c_items').textContent,w:document.getElementById('c_iw').textContent,a:document.getElementById('c_ia').textContent,r:document.getElementById('c_ir').textContent,m:document.getElementById('c_im').textContent,o:document.getElementById('c_io').textContent})");
  await line('items affichés/masqués', "document.getElementById('ith').textContent");
  await line('aucun item m dessiné', "(function(){const iv=itemsVisibles(autoMe||anchor);return iv.list.filter(i=>cat(i.n)==='m').length;})()");

  console.log('\n--- FILTRE 3 : recherche texte ---');
  await ev(setChk('f_im', true));
  await ev(setTxt('f_q', 'sulfur')); await sleep(800);
  await line('S.q', 'S.q');
  await line('items retenus', "(function(){const iv=itemsVisibles(autoMe||anchor);return iv.list.length+' / '+iv.total+' (masqués '+iv.hid+')';})()");
  await line('noms retenus', "(function(){const iv=itemsVisibles(autoMe||anchor);return iv.list.slice(0,6).map(i=>i.n).join(',');})()");
  await ev(setTxt('f_q', ''));

  console.log('\n--- FILTRE 4 : distance max items 60 m ---');
  await ev(setRng('f_idist', 60)); await sleep(800);
  await line('label distance', "document.getElementById('v_idist').textContent");
  await line('items <=60 m', "(function(){const iv=itemsVisibles(autoMe||anchor);return iv.list.length+' retenus, '+iv.hid+' masqués';})()");
  await ev(setRng('f_idist', 0));

  console.log('\n--- FILTRE 5 : distance max joueurs 200 m ---');
  await ev(setRng('f_pdist', 200)); await sleep(800);
  await line('label joueurs', "document.getElementById('v_pdist').textContent");
  await line('joueurs visibles', "(function(){const P=data.players||[];let v=0,h=0;const fi=focusedIndex(),ref=fi>=0?P[fi]:(autoMe||anchor);P.forEach((p,i)=>{if(playerVisible(p,i,fi,ref))v++;else h++;});return v+' visibles / '+h+' masqués';})()");
  await ev(setRng('f_pdist', 0));

  console.log('\n--- CARTE : cap, suivi, boussole, grille, zoom ---');
  await ev(setChk('f_cap', false)); await sleep(400);
  await line('cap off -> rot', "JSON.stringify({cap:S.cap,rotOn:rotOn,rot:rot})");
  await ev(setChk('f_cap', true));
  await ev(setChk('f_follow', false)); await sleep(400);
  await line('suivi off', "JSON.stringify({follow:S.follow,followMe:followMe})");
  await ev(setChk('f_follow', true));
  await ev(setRng('f_zoom', 3.4)); await sleep(400);
  await line('zoom', "JSON.stringify({zoom:S.zoom,scale:scale})");
  await ev(setChk('f_grid', false)); await ev(setChk('f_comp', false)); await sleep(400);
  await line('grille/boussole', "JSON.stringify({grid:S.grid,comp:S.comp})");
  await ev(setChk('f_grid', true)); await ev(setChk('f_comp', true));

  console.log('\n--- RACCOURCIS clavier ---');
  await ev("(function(){const e=new KeyboardEvent('keydown',{key:'g'});dispatchEvent(e);return S.open;})()");
  await line('[G] panneau replié', "JSON.stringify({open:S.open,bodyClass:document.getElementById('guibody').className})");
  await ev("(function(){const e=new KeyboardEvent('keydown',{key:'g'});dispatchEvent(e);return S.open;})()");
  await ev("(function(){const e=new KeyboardEvent('keydown',{key:'m'});dispatchEvent(e);return followMe;})()");
  await line('[M] bascule suivi', "JSON.stringify({follow:S.follow,followMe:followMe})");
  await ev("(function(){const e=new KeyboardEvent('keydown',{key:'m'});dispatchEvent(e);return followMe;})()");
  await ev("(function(){const e=new KeyboardEvent('keydown',{key:'i'});dispatchEvent(e);return S.items;})()");
  await line('[I] bascule items', "JSON.stringify({items:S.items})");
  await ev("(function(){const e=new KeyboardEvent('keydown',{key:'i'});dispatchEvent(e);return S.items;})()");

  console.log('\n--- PERSISTANCE ---');
  await line('localStorage', "localStorage.getItem('rr02.gui') ? localStorage.getItem('rr02.gui').slice(0,120) : 'VIDE'");
  await line('erreurs JS finales', "JSON.stringify({errs:(window.__errs||[]).slice(0,5),rej:(window.__rej||[]).slice(0,5)})");

  const shot = await send('Page.captureScreenshot', { format: 'png' });
  require('fs').writeFileSync('/tmp/gui_panel.png', Buffer.from(shot.data, 'base64'));
  console.log('\nscreenshot -> /tmp/gui_panel.png');
  process.exit(0);
})();
