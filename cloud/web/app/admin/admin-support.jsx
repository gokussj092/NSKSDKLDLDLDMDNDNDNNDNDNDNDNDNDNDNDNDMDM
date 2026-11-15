"use client";
import {useCallback,useEffect,useMemo,useRef,useState} from 'react';
import {useRouter} from 'next/navigation';
const CATEGORY={technical:'Técnico',apk:'Análisis APK',payments:'Pagos',account:'Cuenta',other:'General'};
const STATUS={open:'Pendiente',answered:'Respondido',closed:'Cerrado'};
function avatar(src){
 if(typeof src!=='string')return null;
 if(/^https:\/\/lh[3-6]\.googleusercontent\.com\//.test(src))return src;
 if(/^data:image\/jpeg;base64,[A-Za-z0-9+/]+={0,2}$/.test(src)&&src.length<115000)return src;
 return null;
}
function Initial({name,src}){
 return avatar(src)?<img className="sp-conversation-avatar" src={avatar(src)} alt=""/>:
 <div className="sp-conversation-avatar sp-initial">{name?.slice(0,1)?.toUpperCase()||'?'}</div>;
}
function SenderLabel({message,customLabels={}}){
 const staff=message.sender==='admin';
 const role=customLabels[message.agent?.role]||
  (message.agent?.role==='owner'?'Propietario':message.agent?.role==='admin'?'Administración':
   message.agent?.role==='moderator'?'Moderación':'Soporte');
 return <span>{staff?(message.agent?.name||'SP-DECODE')+' · '+role:'Cliente'}</span>;
}
export default function AdminSupport(){
 const router=useRouter(),endRef=useRef(null);
 const [threads,setThreads]=useState([]),[access,setAccess]=useState(null),[staff,setStaff]=useState([]),
 [customRoles,setCustomRoles]=useState([]),
 [active,setActive]=useState(''),[answer,setAnswer]=useState(''),[busy,setBusy]=useState(false),
 [error,setError]=useState(''),[notice,setNotice]=useState(''),[filter,setFilter]=useState('all'),
 [query,setQuery]=useState('');
 const load=useCallback(async()=>{
  const [r,a]=await Promise.all([
   fetch('/api/admin/support',{credentials:'same-origin',cache:'no-store'}),
   fetch('/api/admin/access',{credentials:'same-origin',cache:'no-store'})]);
  if(r.status===401||a.status===401){router.replace('/admin/login');return;}
  if(!r.ok||!a.ok)throw Error('No se pudieron cargar las conversaciones.');
  const auth=(await a.json()).principal;
  if(auth.mustChangePassword){router.replace('/admin/staff-password');return;}
  setAccess(auth);setThreads((await r.json()).threads||[]);
  if(auth.capabilities?.includes('support.assign')){
   const staffResponse=await fetch('/api/admin/staff',{cache:'no-store'});
   if(staffResponse.ok){
     const payload=await staffResponse.json();
     setStaff(payload.staff||[]);setCustomRoles(payload.roleDefinitions||[]);
   }
  }
 },[router]);
 useEffect(()=>{load().catch(e=>setError(e.message));const t=setInterval(()=>load().catch(()=>{}),15000);return()=>clearInterval(t);},[load]);
 const customLabels=Object.fromEntries(customRoles.map(r=>[r.code,r.name]));
 const selected=threads.find(t=>t.id===active);
 useEffect(()=>{endRef.current?.scrollIntoView({block:'end',behavior:'smooth'});},
   [active,selected?.messages?.length]);
 const counts={all:threads.length,open:threads.filter(x=>x.status==='open').length,
  answered:threads.filter(x=>x.status==='answered').length,closed:threads.filter(x=>x.status==='closed').length};
 const visible=useMemo(()=>threads.filter(x=>(filter==='all'||x.status===filter)&&
   (!query||[x.subject,x.name,x.username,x.assigned_name].some(v=>v?.toLowerCase().includes(query.toLowerCase())))),
  [threads,filter,query]);
 async function mutate(body){
  setBusy(true);setError('');setNotice('');
  try{
   const r=await fetch('/api/admin/support',{method:'POST',cache:'no-store',credentials:'same-origin',
    headers:{'Content-Type':'application/json','X-SPDecode-Admin-Action':'1'},body:JSON.stringify(body)});
   const data=await r.json();if(!r.ok)throw Error(data?.error?.code==='SUPPORT_NOT_ASSIGNED'?
     'Solo el agente asignado puede responder este ticket.':'No se pudo guardar la operación.');
   setAnswer('');setNotice('Conversación actualizada.');await load();
  }catch(e){setError(e.message);}finally{setBusy(false);}
 }
 const reply=()=>{if(selected&&answer.trim())mutate({threadId:selected.id,action:'reply',message:answer.trim()});};
 const assign=updates=>{if(selected)mutate({action:'assign',threadId:selected.id,
  assignedId:updates.assignedId===undefined?(selected.assigned_staff_id||null):updates.assignedId,
  priority:updates.priority??selected.priority??'normal'});};
 return <div className="sp-admin-commerce sp-support-admin">
  <section className="sp-admin-commerce-hero"><div>
   <span className="sp-admin-commercial-kicker">ATENCIÓN AL CLIENTE</span>
   <h2>Centro de conversaciones</h2>
   <p>Responde, asigna y supervisa solicitudes de forma segura.</p>
  </div><span className="sp-support-pill">{counts.open} pendientes</span></section>
  {error&&<p className="form-message error" role="alert">{error}</p>}
  {notice&&<p className="form-message" role="status">{notice}</p>}
  <div className="sp-chat-workspace">
   <aside className="sp-chat-inbox" aria-label="Bandeja de conversaciones">
    <header><h2>Conversaciones</h2><small>{counts.all} en total</small></header>
    <input className="sp-chat-search" value={query} onChange={e=>setQuery(e.target.value)}
     placeholder="Buscar conversación…" aria-label="Buscar conversaciones"/>
    <div className="sp-chat-filters">{Object.entries({all:'Todas',open:'Pendientes',
      answered:'Respondidas',closed:'Cerradas'}).map(([key,label])=><button type="button" key={key}
     aria-pressed={filter===key} onClick={()=>setFilter(key)}>{label} <small>{counts[key]}</small></button>)}</div>
    <div className="sp-chat-inbox-scroll">{visible.map(t=>{
     const last=t.messages?.[t.messages.length-1];
     return <button type="button" className={'sp-chat-thread '+(active===t.id?'selected':'')}
      key={t.id} onClick={()=>{setActive(t.id);setAnswer('');}}>
      <Initial name={t.name} src={t.avatar}/>
      <span className="sp-chat-thread-content">
       <span className="sp-chat-thread-title"><strong>{t.name||'Cuenta'}</strong>
        <time>{new Date(t.last_message_at).toLocaleDateString('es-MX',{day:'2-digit',month:'short'})}</time></span>
       <span className="sp-chat-thread-subtitle">{t.subject}</span>
       <span className="sp-chat-preview">{last?.text||CATEGORY[t.category]||'Conversación'}</span>
       <span className="sp-chat-ticket-footer"><span className={'sp-chat-status '+t.status}>{STATUS[t.status]}</span>
        {t.assigned_name&&<span>{t.assigned_name}</span>}</span>
      </span>
     </button>;
    })}{!visible.length&&<p className="sp-chat-empty">No hay conversaciones para este filtro.</p>}</div>
   </aside>
   <section className="sp-chat-dialog" aria-label="Conversación de soporte">
    {!selected?<div className="sp-chat-placeholder">
     <span className="sp-chat-placeholder-icon">✉</span><h2>Selecciona un mensaje</h2>
     <p>Elige una conversación para consultar su historial y responder.</p>
    </div>:<>
     <header className="sp-chat-dialog-header">
      <Initial name={selected.name} src={selected.avatar}/>
      <div><h2>{selected.name||'Cliente'}</h2><p>{selected.username?'@'+selected.username+' · ':''}{selected.subject}</p></div>
      <span className={'sp-chat-status '+selected.status}>{STATUS[selected.status]}</span>
     </header>
     {access?.capabilities?.includes('support.assign')&&<div className="sp-chat-assignment">
      <label>Agente<select disabled={busy} value={selected.assigned_staff_id||''}
       onChange={e=>assign({assignedId:e.target.value||null})}>
       <option value="">Sin asignar</option>{staff.filter(x=>x.enabled&&!x.mustChangePassword&&
        (['admin','support','moderator'].includes(x.role)||
         customRoles.some(r=>r.code===x.role&&r.enabled&&r.permissions.includes('support.write')))).map(x=>
         <option key={x.id} value={x.id}>{x.name} · @{x.username}</option>)}
      </select></label>
      <label>Prioridad<select disabled={busy} value={selected.priority||'normal'}
       onChange={e=>assign({priority:e.target.value})}>
       <option value="low">Baja</option><option value="normal">Normal</option><option value="high">Alta</option>
      </select></label>
     </div>}
     <div className="sp-chat-message-scroller" role="log" aria-live="polite">
      {selected.messages?.map(m=><div key={m.id} className={'sp-chat-bubble '+(m.sender==='admin'?'outgoing':'incoming')}>
       <strong><SenderLabel message={m} customLabels={customLabels}/></strong>
       <p>{m.text}</p><time>{new Date(m.at).toLocaleString('es-MX',{hour:'2-digit',minute:'2-digit'})}</time>
      </div>)}
      <div ref={endRef}/>
     </div>
     {selected.status!=='closed'?<div className="sp-chat-compose">
      <textarea value={answer} onChange={e=>setAnswer(e.target.value)} maxLength={4000}
       rows={1} placeholder="Escribe un mensaje…" aria-label="Respuesta al cliente"
       onKeyDown={e=>{if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();reply();}}}/>
      <button type="button" className="sp-chat-send" disabled={!answer.trim()||busy}
       aria-label="Enviar respuesta" title="Enviar respuesta" onClick={reply}>
       <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="21" height="21"
        aria-hidden="true"><path d="M22 2L11 13M22 2l-7 20-4-9-9-4z"/></svg>
      </button>
     </div>:<div className="sp-chat-closed">Conversación cerrada. Puedes reabrirla.</div>}
     {access?.capabilities?.includes('support.write')&&<footer className="sp-chat-footer">
      <button className="button" type="button" disabled={busy}
       onClick={()=>mutate({threadId:selected.id,action:selected.status==='closed'?'reopen':'close'})}>
       {selected.status==='closed'?'Reabrir conversación':'Cerrar conversación'}
      </button>
     </footer>}
    </>}
   </section>
  </div>
 </div>;
}