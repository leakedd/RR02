// Capture propre du calque items : reload, zoom 2.2, cam sur le nuage d'items, comptage + pixels
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
let id=0,pending=new Map(),ws;
function send(m,p){ return new Promise((res,rej)=>{ const i=++id; pending.set(i,{res,rej}); ws.send(JSON.stringify({id:i,method:m,params:p||{}})); }); }
const ev=async e=>{ const r=await send('Runtime.evaluate',{expression:e,returnByValue:true,awaitPromise:true});
  return r.exceptionDetails?(r.exceptionDetails.exception&&r.exceptionDetails.exception.description):r.result.value; };
(async()=>{
  const ts=await (await fetch('http://127.0.0.1:9333/json')).json();
  const t=ts.find(x=>x.type==='page'&&x.url.includes('8791'));
  ws=new WebSocket(t.webSocketDebuggerUrl);
  ws.onmessage=e=>{ const m=JSON.parse(e.data); if(m.id&&pending.has(m.id)){const p=pending.get(m.id);pending.delete(m.id);
    m.error?p.rej(new Error(JSON.stringify(m.error))):p.res(m.result);} };
  await new Promise(r=>ws.onopen=r);
  await send('Runtime.enable'); await send('Page.enable');
  await send('Emulation.setDeviceMetricsOverride',{width:1600,height:900,deviceScaleFactor:1,mobile:false});
  await send('Page.reload',{ignoreCache:true}); await sleep(2600);
  console.log('showItems au chargement =',await ev('showItems'));
  // centre + zoom sur le nuage d'items
  await ev(`(function(){const I=data.items||[];if(!I.length)return 'vide';
     cam.x=I.reduce((a,i)=>a+i.x,0)/I.length; cam.z=I.reduce((a,i)=>a+i.z,0)/I.length;
     scale=3.0; return 'cam('+cam.x.toFixed(0)+','+cam.z.toFixed(0)+') scale=2.2';})()`).then(v=>console.log('cam:',v));
  await sleep(600);
  console.log('comptage in-page:',await ev(`(function(){const I=data.items||[];let vis=0;
     I.forEach(i=>{const s=w2s(i.x,i.z); if(s[0]>=0&&s[0]<=1600&&s[1]>=0&&s[1]<=900) vis++;}); return vis+' / '+I.length;})()`));
  console.log('HUD items:',await ev(`document.getElementById('it').textContent+' | nearest: '+document.getElementById('itn').textContent`));
  // comptage de pixels non-fond dans la zone carte (hors panneaux)
  console.log('pixels colorés (zone carte):',await ev(`(function(){const g=ctx.getImageData(340,20,900,760).data;
     let orange=0,jaune=0,vert=0,rose=0,gris=0;
     for(let i=0;i<g.length;i+=4){const r=g[i],gg=g[i+1],b=g[i+2],a=g[i+3]; if(a<200) continue;
       if(r>200&&gg>120&&gg<190&&b<90) orange++;
       else if(r>210&&gg>200&&b<110) jaune++;
       else if(r<110&&gg>170&&b>120&&b<190) vert++;
       else if(r>220&&gg>90&&gg<150&&b>150) rose++;
     } return JSON.stringify({orange,jaune,vert,rose}); })()`));
  const s=await send('Page.captureScreenshot',{format:'png'});
  require('fs').writeFileSync('/tmp/radtest_items2.png',Buffer.from(s.data,'base64'));
  console.log('capture: /tmp/radtest_items2.png');
  process.exit(0);
})().catch(e=>{console.log('ERREUR',e.message);process.exit(1);});
