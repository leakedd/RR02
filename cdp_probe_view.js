// cdp_probe_view.js — ce que l'overlay dessine REELLEMENT (cam, scale, projection des joueurs)
const http=require('http'), fs=require('fs');
const get=u=>new Promise((res,rej)=>{http.get(u,r=>{let d='';r.on('data',c=>d+=c);r.on('end',()=>res(JSON.parse(d)));}).on('error',rej);});
(async()=>{
  const list=await get('http://127.0.0.1:9333/json/list');
  const t=list.find(x=>x.type==='page');
  const ws=new WebSocket(t.webSocketDebuggerUrl);
  let id=0; const pend={};
  const send=(m,p={})=>new Promise(r=>{const i=++id;pend[i]=r;ws.send(JSON.stringify({id:i,method:m,params:p}));});
  ws.onmessage=e=>{const m=JSON.parse(e.data); if(m.id&&pend[m.id]){pend[m.id](m.result);delete pend[m.id];}};
  await new Promise(r=>ws.onopen=r);
  await send('Page.enable'); await send('Runtime.enable');
  await send('Page.navigate',{url:'http://127.0.0.1:8789/'});
  await new Promise(r=>setTimeout(r,6000));
  const q=`JSON.stringify({cam:cam,scale:scale,rotOn:rotOn,rot:rot,rotTgt:rotTgt,n:(data.players||[]).length,
     proj:(data.players||[]).slice(0,6).map(p=>{const s=w2s(p.x,p.z);return {x:p.x,z:p.z,sx:isFinite(s[0])?Math.round(s[0]):'NaN',sy:isFinite(s[1])?Math.round(s[1]):'NaN'};}),
     canvas:[document.querySelector('canvas').width,document.querySelector('canvas').height]})`;
  const r=await send('Runtime.evaluate',{expression:q,returnByValue:true});
  console.log('ETAT:', r.result.value);
  const shot=await send('Page.captureScreenshot',{format:'png'});
  fs.writeFileSync('/tmp/view_check.png', Buffer.from(shot.data,'base64'));
  console.log('shot: /tmp/view_check.png');
  ws.close(); process.exit(0);
})();
