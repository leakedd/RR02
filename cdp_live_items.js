// cdp_live_items.js — capture de l'overlay LIVE (WebSocket natif Node)
const http=require('http'), fs=require('fs');
const get=u=>new Promise((res,rej)=>{http.get(u,r=>{let d='';r.on('data',c=>d+=c);r.on('end',()=>res(d));}).on('error',rej);});
async function main(){
  const list=JSON.parse(await get('http://127.0.0.1:9333/json/list'));
  let t=list.find(x=>x.type==='page'&&x.webSocketDebuggerUrl);
  if(!t){ // cree un onglet
    t=JSON.parse(await get('http://127.0.0.1:9333/json/new?about:blank'));
  }
  const ws=new globalThis.WebSocket(t.webSocketDebuggerUrl);
  let id=0; const pend={};
  ws.addEventListener('message',ev=>{const o=JSON.parse(ev.data); if(o.id&&pend[o.id]){pend[o.id](o.result); delete pend[o.id];}});
  await new Promise(r=>ws.addEventListener('open',r));
  const send=(method,params={})=>new Promise(r=>{const i=++id;pend[i]=r;ws.send(JSON.stringify({id:i,method,params}));});
  await send('Page.enable'); await send('Runtime.enable');
  await send('Page.navigate',{url:'http://127.0.0.1:8789/'});
  await new Promise(r=>setTimeout(r,4000));
  const js=`(async()=>{const t=await (await fetch('/radar.json?x='+Math.random())).json();
    const h=document.getElementById('hud');
    return JSON.stringify({players:t.players.length,items:(t.items||[]).length,
      items:(t.items||[]).slice(0,4),hud:h?h.innerText.replace(/\\n/g,' | ').slice(0,200):'sans hud'});})()`;
  const st=await send('Runtime.evaluate',{expression:js,awaitPromise:true,returnByValue:true});
  console.log('ETAT:', (st.result&&st.result.value)||JSON.stringify(st));
  const js2=`(()=>{let r=[]; if(typeof scale!=='undefined'){scale=3.2;r.push('scale3.2');}
    if(typeof data!=='undefined'&&data.players&&data.players[0]){cam.x=data.players[0].x;cam.z=data.players[0].z;r.push('cam_centre_joueur');}
    if(typeof draw==='function'){draw();r.push('draw');} return r.join(',');})()`;
  const z=await send('Runtime.evaluate',{expression:js2,returnByValue:true});
  console.log('ZOOM:', (z.result&&z.result.value)||JSON.stringify(z));
  await new Promise(r=>setTimeout(r,1000));
  const shot=await send('Page.captureScreenshot',{format:'png'});
  fs.writeFileSync('/tmp/live_items.png',Buffer.from(shot.data,'base64'));
  console.log('capture: /tmp/live_items.png', fs.statSync('/tmp/live_items.png').size,'octets');
  ws.close(); process.exit(0);
}
main().catch(e=>{console.error('ERR',e.message);process.exit(1);});
