// cdp_rot_test.js — vérifie la rotation du radar (cap en haut), la boussole et le clic en mode tourné
const http=require('http'), fs=require('fs');
const get=u=>new Promise((res,rej)=>{http.get(u,r=>{let d='';r.on('data',c=>d+=c);r.on('end',()=>res(d));}).on('error',rej);});
const sleep=ms=>new Promise(r=>setTimeout(r,ms));
async function main(){
  const list=JSON.parse(await get('http://127.0.0.1:9333/json/list'));
  let t=list.find(x=>x.type==='page'&&x.webSocketDebuggerUrl);
  const ws=new globalThis.WebSocket(t.webSocketDebuggerUrl);
  let id=0; const pend={};
  ws.addEventListener('message',ev=>{const o=JSON.parse(ev.data); if(o.id&&pend[o.id]){pend[o.id](o.result);delete pend[o.id];}});
  await new Promise(r=>ws.addEventListener('open',r));
  const send=(m,p={})=>new Promise(r=>{const i=++id;pend[i]=r;ws.send(JSON.stringify({id:i,method:m,params:p}));});
  const ev=async expr=>{const r=await send('Runtime.evaluate',{expression:expr,returnByValue:true,awaitPromise:true});return r&&r.result?r.result.value:null;};
  const shot=async f=>{const s=await send('Page.captureScreenshot',{format:'png'});fs.writeFileSync(f,Buffer.from(s.data,'base64'));return fs.statSync(f).size;};

  await send('Page.enable');await send('Runtime.enable');
  await send('Page.navigate',{url:'http://127.0.0.1:8789/'});
  await sleep(4000);
  console.log('etat initial:',await ev(`JSON.stringify({rotOn,rot:+(rot*180/Math.PI).toFixed(1),n:(data.players||[]).length,cap:document.getElementById('rotv').textContent})`));

  // 1) cap force a 90 deg (est) pour verifier la rotation visuelle + la boussole
  console.log('force 90deg:',await ev(`rotOn=true;rot=rotTgt=Math.PI/2;draw();JSON.stringify({N:document.getElementById('rotv').textContent})`));
  await sleep(600); console.log('png rot90:',await shot('/tmp/rot_90.png'));

  // 2) clic reel sur un joueur EN MODE TOURNE -> le suivi doit se poser sur ce joueur
  const pick=JSON.parse(await ev(`(()=>{const P=data.players||[];let k=P.findIndex(p=>p.on);if(k<0)k=0;
     const p=P[k];const s=w2s(p.x,p.z);return JSON.stringify({x:Math.round(s[0]),y:Math.round(s[1]),id:p.id,idx:k,txt:'#'+k});})()`));
  console.log('cible clic:',JSON.stringify(pick));
  await send('Input.dispatchMouseEvent',{type:'mousePressed',x:pick.x,y:pick.y,button:'left',clickCount:1});
  await send('Input.dispatchMouseEvent',{type:'mouseReleased',x:pick.x,y:pick.y,button:'left',clickCount:1});
  await sleep(700);
  console.log('apres clic:',await ev(`JSON.stringify({focusId:focusId,attendu:${pick.id},ok:(focusId===${pick.id}),hud:document.getElementById('me').textContent})`));
  console.log('png focus:',await shot('/tmp/rot_focus.png'));

  // 3) touche R reelle -> bascule nord fixe
  await send('Input.dispatchKeyEvent',{type:'keyDown',key:'r',code:'KeyR',windowsVirtualKeyCode:82,nativeVirtualKeyCode:82});
  await send('Input.dispatchKeyEvent',{type:'keyUp',key:'r',code:'KeyR',windowsVirtualKeyCode:82,nativeVirtualKeyCode:82});
  await sleep(500);
  console.log('apres touche R:',await ev(`JSON.stringify({rotOn,rot:+(rot*180/Math.PI).toFixed(1),cap:document.getElementById('rotv').textContent})`));
  console.log('png nord:',await shot('/tmp/rot_north.png'));

  // 4) cap recalcule par deplacement simule (2 positions successives) -> rotation auto
  const mv=await ev(`(()=>{ focusId=null; rotOn=true; rot=rotTgt=0; lastRotFix=null;
     const P=(data.players||[]); const p=P.find(x=>x.on)||P[0]; if(!p) return 'aucun joueur';
     lastRotFix={x:p.x,z:p.z};                 // ancre
     return JSON.stringify({id:p.id,x:p.x,z:p.z}); })()`);
  console.log('joueur pour test deplacement:',mv);
  // simule un deplacement de 10 m vers +X (est) en injectant une fausse position dans data
  console.log('deplacement simule +X:',await ev(`(()=>{const P=data.players||[];const k=P.findIndex(p=>p.on);const p=P[k];
     lastRotFix={x:p.x,z:p.z}; p.x=p.x+10;                 // deplace de 10 m vers l'est
     const cy=(data.cam&&isFinite(data.cam.yaw))?1:0;
     const dx=p.x-lastRotFix.x,dz=p.z-lastRotFix.z; rotTgt=Math.atan2(dx,dz); lastRotFix={x:p.x,z:p.z};
     return JSON.stringify({rotTgt_deg:+(rotTgt*180/Math.PI).toFixed(1)});})()`));
  await sleep(900);
  console.log('rotation appliquee:',await ev(`JSON.stringify({rot_deg:+(rot*180/Math.PI).toFixed(1),cap:document.getElementById('rotv').textContent})`));
  console.log('png mouvement:',await shot('/tmp/rot_move.png'));

  ws.close();process.exit(0);
}
main().catch(e=>{console.error('ERR',e.message);process.exit(1);});
