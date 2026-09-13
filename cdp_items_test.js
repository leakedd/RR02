// Vérif E2E du calque items (Chrome CDP 9333) : HUD, clic réel sur un item, capture
const PORT=9333, URL_MATCH='8791';
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function targets(){ const r=await fetch(`http://127.0.0.1:${PORT}/json`); return r.json(); }
let id=0, pending=new Map(), ws;
function send(method,params){ return new Promise((res,rej)=>{ const i=++id; pending.set(i,{res,rej});
  ws.send(JSON.stringify({id:i,method,params:params||{}})); }); }
const evalJS=async expr=>{ const r=await send('Runtime.evaluate',{expression:expr,returnByValue:true,awaitPromise:true});
  if(r.exceptionDetails) return {err:JSON.stringify(r.exceptionDetails.exception&&r.exceptionDetails.exception.description||r.exceptionDetails.text)};
  return r.result.value; };
(async()=>{
  let t=null;
  for(let i=0;i<40 && !t;i++){ try{ const ts=await targets(); t=(ts||[]).find(x=>x.type==='page'&&x.url.includes(URL_MATCH)); }catch(e){} if(!t) await sleep(500); }
  if(!t){ console.log('PAGE_INTROUVABLE'); process.exit(1); }
  console.log('cible:',t.url);
  ws=new WebSocket(t.webSocketDebuggerUrl);
  ws.onmessage=ev=>{ const m=JSON.parse(ev.data); if(m.id&&pending.has(m.id)){ const p=pending.get(m.id); pending.delete(m.id);
    m.error?p.rej(new Error(JSON.stringify(m.error))):p.res(m.result); } };
  await new Promise(r=>ws.onopen=r);
  await send('Runtime.enable'); await send('Page.enable');
  await send('Emulation.setDeviceMetricsOverride',{width:1600,height:900,deviceScaleFactor:1,mobile:false});
  await send('Page.reload',{ignoreCache:true}); await sleep(2500);
  const hud=await evalJS(`JSON.stringify({on:document.getElementById('on').textContent,items:document.getElementById('it').textContent,
     nearest:document.getElementById('itn').textContent, age:document.getElementById('age').textContent,
     total:document.getElementById('n').textContent, players:(data.players||[]).length, items:(data.items||[]).length})`);
  console.log('HUD:',hud);
  const p=await evalJS(`(function(){ const it=(data.items||[])[3]; const s=w2s(it.x,it.z); return JSON.stringify({n:it.n,x:Math.round(s[0]),y:Math.round(s[1])}); })()`);
  console.log('item ciblé (3e):',p);
  const o=JSON.parse(p);
  if(o.x>5&&o.y>5&&o.x<1590&&o.y<890){
    await send('Input.dispatchMouseEvent',{type:'mousePressed',x:o.x,y:o.y,button:'left',clickCount:1});
    await send('Input.dispatchMouseEvent',{type:'mouseReleased',x:o.x,y:o.y,button:'left',clickCount:1});
    await sleep(400);
    console.log('tip après clic item:',await evalJS(`document.getElementById('tip').textContent.trim().slice(0,90)`));
    console.log('ancre:',await evalJS(`anchor?JSON.stringify({x:+anchor.x.toFixed(1),z:+anchor.z.toFixed(1)}):'null'`));
  } else console.log('item hors écran, clic sauté');
  // bascule du calque (touche I)
  await send('Input.dispatchKeyEvent',{type:'keyDown',key:'i',text:'i'});
  await sleep(300);
  console.log('après touche I ->',await evalJS(`document.getElementById('it').textContent+' | actif='+showItems`));
  await send('Input.dispatchKeyEvent',{type:'keyDown',key:'i',text:'i'}); await sleep(300);
  console.log('re-touche I ->',await evalJS(`document.getElementById('it').textContent+' | actif='+showItems`));
  // zoom in pour montrer les libellés
  await evalJS(`scale=3.4; cam.x=0; cam.z=0; 'ok'`); await sleep(400);
  const shot=await send('Page.captureScreenshot',{format:'png'});
  require('fs').writeFileSync('/tmp/radtest_items.png',Buffer.from(shot.data,'base64'));
  console.log('capture: /tmp/radtest_items.png');
  const errs=await evalJS(`JSON.stringify((window.__errs||[]).slice(0,3))`);
  console.log('erreurs JS:',errs);
  process.exit(0);
})().catch(e=>{ console.log('ERREUR',e.message); process.exit(1); });
