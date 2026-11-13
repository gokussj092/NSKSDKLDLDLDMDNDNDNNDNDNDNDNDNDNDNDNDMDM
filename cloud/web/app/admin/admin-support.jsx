"use client";
import {useCallback,useEffect,useState} from 'react';
import {useRouter} from 'next/navigation';
const CATEGORY={technical:'Soporte técnico',apk:'Análisis APK',payments:'Compras y pagos',account:'Cuenta',other:'Otros'};
function avatar(src){
 if(typeof src!=='string')return null;
 if(/^https:\/\/lh[3-6]\.googleusercontent\.com\//.test(src))return src;
 if(/^data:image\/jpeg;base64,[A-Za-z0-9+/]+={0,2}$/.test(src)&&src.length<115000)return src;
 return null;
}
export default function AdminSupport(){
 const router=useRouter(),[threads,setThreads]=useState([]),[active,setActive]=useState(''),
 [answer,setAnswer]=useState(''),[busy,setBusy]=useState(false),[error,setError]=useState(''),
 [notice,setNotice]=useState('');
 const load=useCallback(async()=>{
  const r=await fetch('/api/admin/support',{credentials:'same-origin',cache:'no-store'});
  if(r.status===401){router.replace('/admin/login');return;}
  if(!r.ok)throw Error('No se pudieron cargar las conversaciones.');
  const d=await r.json();setThreads(d.threads||[]);
 },[router]);
 useEffect(()=>{load().catch(e=>setError(e.message));const t=setInterval(()=>load().catch(()=>{}),15000);return()=>clearInterval(t);},[load]);
 const selected=threads.find(t=>t.id===active);
 async function submit(action){
  if(!selected)return;setBusy(true);setError('');setNotice('');
  try{
   const r=await fetch('/api/admin/support',{method:'POST',credentials:'same-origin',cache:'no-store',
    headers:{'Content-Type':'application/json','X-SPDecode-Admin-Action':'1'},
    body:JSON.stringify({threadId:selected.id,action,...(action==='reply'?{message:answer}:{})})});
   if(!r.ok)throw Error('No se pudo guardar la respuesta.');
   setAnswer('');setNotice('Conversación actualizada.');await load();
  }catch(e){setError(e.message);}finally{setBusy(false);}
 }
 return <div className="sp-admin-commerce">
  <section className="sp-admin-commerce-hero"><div>
   <span className="sp-admin-commercial-kicker">SP-DECODE · ASISTENCIA</span>
   <h2>Mensajes de soporte</h2>
   <p>Conversaciones privadas, incidencias y respuestas a usuarios.</p>
  </div></section>
  {error&&<p className="form-message error" role="alert">{error}</p>}
  {notice&&<p className="form-message" role="status">{notice}</p>}
  <div className="sp-support-layout">
   <section className="admin-card sp-support-list" aria-label="Conversaciones">
    <h2>Bandeja de entrada</h2>
    {!threads.length?<p className="muted">No hay conversaciones.</p>:threads.map(t=>
     <button type="button" key={t.id} className={'sp-support-thread '+(active===t.id?'selected':'')}
      onClick={()=>{setActive(t.id);setAnswer('');}}>
      {avatar(t.avatar)?<img src={avatar(t.avatar)} alt="" width="40" height="40"/>:<span className="sp-support-initial">{t.name?.slice(0,1)||'?'}</span>}
      <span><strong>{t.name||'Cuenta'} · {t.username?'@'+t.username:'Usuario'}</strong>
      <small>{t.subject} · {CATEGORY[t.category]||t.category}</small></span>
      <span className="sp-support-status">{t.status==='answered'?'Respondido':t.status==='closed'?'Cerrado':'Abierto'}</span>
     </button>)}
   </section>
   <section className="admin-card sp-support-chat" aria-label="Chat de soporte">
    {!selected?<p className="muted">Selecciona una conversación.</p>:<>
     <header><h2>{selected.subject}</h2>
      <p className="muted">{selected.name} · {selected.username?'@'+selected.username:''}</p>
     </header>
     <div className="sp-support-history" role="log" aria-live="polite">
      {selected.messages.map(m=><div key={m.id} className={'sp-support-message '+m.sender}>
       <small>{m.sender==='admin'?((m.agent?.name||'SP-DECODE')+' · '+(m.agent?.role==='owner'?'Administrador':m.agent?.role==='admin'?'Administración':'Soporte')):'Usuario'}</small>
       <p>{m.text}</p><time>{new Date(m.at).toLocaleString('es-MX')}</time>
      </div>)}
     </div>
     {selected.status!=='closed'&&<>
      <textarea rows={4} maxLength={4000} value={answer} onChange={e=>setAnswer(e.target.value)}
       placeholder="Escribe tu respuesta…" aria-label="Responder al usuario"/>
      <button className="button" type="button" disabled={!answer.trim()||busy}
       onClick={()=>submit('reply')}>Enviar respuesta</button>
     </>}
     <div className="sp-support-options">
      <button className="button" type="button" disabled={busy} onClick={()=>submit(selected.status==='closed'?'reopen':'close')}>
       {selected.status==='closed'?'Reabrir conversación':'Cerrar conversación'}
      </button>
     </div>
    </>}
   </section>
  </div>
 </div>;
}