"use client";
import {useCallback,useEffect,useMemo,useRef,useState} from 'react';
import {useRouter} from 'next/navigation';
import Link from 'next/link';
const CATEGORY={technical:'Técnico',apk:'Análisis APK',payments:'Pagos',account:'Cuenta',other:'General'};
const STATUS={open:'Pendiente',answered:'Respondido',closed:'Cerrado'};
const PRIORITY={low:'Baja',normal:'Normal',high:'Alta'};
const SUSPENSION_REASONS={TOO_MANY_TICKETS:'demasiados tickets en un día',
  too_many_tickets:'demasiados tickets en un día'};
const DRAFT_KEY='spdecode-support-drafts-v1';
function readDrafts(){
 try{return JSON.parse(localStorage.getItem(DRAFT_KEY)||'{}')||{};}catch{return {};}
}
function writeDraft(id,text){
 try{
  const drafts=readDrafts();
  if(text)drafts[id]=text;else delete drafts[id];
  localStorage.setItem(DRAFT_KEY,JSON.stringify(drafts));
 }catch{}
}
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
   message.agent?.role==='moderator'?'Moderación':'Asistente');
 return <span>{staff?(message.agent?.name||'Yamada')+' · '+role:'Cliente'}</span>;
}
function isSuspended(t){
 if(!t?.suspension)return false;
 if(!t.suspension.suspendedUntil)return true;
 return new Date(t.suspension.suspendedUntil).getTime()>Date.now();
}
function suspensionLabel(s){
 if(!s?.suspendedUntil)return 'Suspendido';
 const ms=new Date(s.suspendedUntil).getTime()-Date.now();
 if(!(ms>0))return 'Suspendido';
 if(ms<3600000)return 'Suspendido · quedan '+Math.max(1,Math.ceil(ms/60000))+' min';
 return 'Suspendido · hasta '+new Date(s.suspendedUntil)
  .toLocaleTimeString('es-MX',{hour:'2-digit',minute:'2-digit'});
}
function suspensionDetail(s){
 const reason=SUSPENSION_REASONS[s?.reason]||s?.reason||'demasiados tickets en un día';
 return 'Motivo: '+reason+' · Suspensiones previas: '+(s?.priorCount??0);
}
function errorText(data,status,fallback){
 const code=data?.error?.code;
 if(typeof navigator!=='undefined'&&!navigator.onLine)
  return 'Sin conexión a internet. Revisa tu red y reintenta.';
 if(code==='SUPPORT_NOT_ASSIGNED')return 'Solo el agente asignado puede responder este ticket.';
 if(code==='SUPPORT_THREAD_CLOSED'||status===409)
  return 'La conversación está cerrada. Reábrela antes de responder.';
 if(code==='SUPPORT_RATE_LIMITED'||code==='SUPPORT_SUSPENDED'||status===429)
  return 'Demasiadas solicitudes. Espera un momento y vuelve a intentarlo.';
 if(code==='SUPPORT_NOT_FOUND'||status===404)
  return 'La conversación ya no existe. Recarga la bandeja.';
 if(code==='INVALID_REQUEST'||code==='INVALID_SUBJECT')
  return 'Revisa los datos: el título debe tener entre 4 y 100 caracteres.';
 if(code==='FORBIDDEN'||status===403)return 'No tienes permiso para realizar esta acción.';
 if(code==='UNAUTHORIZED'||status===401)return 'Tu sesión expiró. Vuelve a iniciar sesión.';
 return fallback;
}
function fullDate(value){
 const d=new Date(value);
 if(Number.isNaN(d.getTime()))return '—';
 return d.toLocaleString('es-MX',{day:'2-digit',month:'short',year:'numeric',
  hour:'2-digit',minute:'2-digit'});
}
export default function AdminSupport(){
 const router=useRouter(),endRef=useRef(null),scrollerRef=useRef(null),searchRef=useRef(null),
  nearBottomRef=useRef(true),justOpenedRef=useRef(false);
 const [threads,setThreads]=useState([]),[unreadTotal,setUnreadTotal]=useState(0),
 [access,setAccess]=useState(null),[customRoles,setCustomRoles]=useState([]),
 [active,setActive]=useState(''),[answer,setAnswer]=useState(''),[busy,setBusy]=useState(false),
 [error,setError]=useState(''),[notice,setNotice]=useState(''),[filter,setFilter]=useState('all'),
 [query,setQuery]=useState(''),[loading,setLoading]=useState(true),[loadError,setLoadError]=useState(''),
 [refreshError,setRefreshError]=useState(false),
 [editingTitle,setEditingTitle]=useState(false),[titleDraft,setTitleDraft]=useState(''),
 [showSuspDetail,setShowSuspDetail]=useState(false);
 const threadsRef=useRef(threads);
 useEffect(()=>{threadsRef.current=threads;},[threads]);
 const load=useCallback(async()=>{
  try{
   const [r,a]=await Promise.all([
    fetch('/api/admin/support',{credentials:'same-origin',cache:'no-store'}),
    fetch('/api/admin/access',{credentials:'same-origin',cache:'no-store'})]);
   if(r.status===401||a.status===401){router.replace('/admin/login');return;}
   if(!r.ok||!a.ok)throw Error('No se pudieron cargar las conversaciones.');
   const auth=(await a.json()).principal;
   if(auth.mustChangePassword){router.replace('/admin/staff-password');return;}
   const payload=await r.json();
   setAccess(auth);setThreads(payload.threads||[]);setUnreadTotal(payload.unreadTotal||0);
   setLoadError('');setRefreshError(false);
   if(auth.capabilities?.includes('staff.read')){
    const staffResponse=await fetch('/api/admin/staff',{cache:'no-store'});
    if(staffResponse.ok){
     const staffPayload=await staffResponse.json();
     setCustomRoles(staffPayload.roleDefinitions||[]);
    }
   }
  }catch(e){
   if(!threadsRef.current.length)setLoadError(e.message||'No se pudieron cargar las conversaciones.');
   else setRefreshError(true);
   throw e;
  }
 },[router]);
 useEffect(()=>{setLoading(true);load().catch(()=>{}).finally(()=>setLoading(false));
  const t=setInterval(()=>load().catch(()=>{}),15000);return()=>clearInterval(t);},[load]);
 const customLabels=Object.fromEntries(customRoles.map(r=>[r.code,r.name]));
 const selected=threads.find(t=>t.id===active);
 const canWrite=access?.capabilities?.includes('support.write');
 const markRead=useCallback(async threadId=>{
  const thread=threadsRef.current.find(t=>t.id===threadId);
  if(!thread||!(thread.unread>0))return;
  try{
   const r=await fetch('/api/admin/support',{method:'POST',cache:'no-store',credentials:'same-origin',
    headers:{'Content-Type':'application/json','X-SPDecode-Admin-Action':'1'},
    body:JSON.stringify({action:'read',threadId})});
   if(!r.ok)return;
   setThreads(ts=>ts.map(t=>t.id===threadId?{...t,unread:0}:t));
   setUnreadTotal(v=>Math.max(0,v-(thread.unread||0)));
  }catch{}
 },[]);
 // Al abrir un hilo (y cuando llegan mensajes nuevos mientras se está viendo) se marca leído.
 useEffect(()=>{
  if(active&&selected?.unread>0)markRead(active);
 },[active,selected?.unread,selected?.messages?.length,markRead]);
 // Borrador del hilo activo: persiste en localStorage y se conserva al cambiar de hilo.
 useEffect(()=>{
  if(!active)return;
  setAnswer(readDrafts()[active]||'');
  setEditingTitle(false);setShowSuspDetail(false);justOpenedRef.current=true;
 },[active]);
 // Solo se baja al final si Yamada ya estaba al final (o acaba de abrir el hilo).
 useEffect(()=>{
  const el=scrollerRef.current;if(!el||!selected)return;
  if(justOpenedRef.current){el.scrollTop=el.scrollHeight;justOpenedRef.current=false;return;}
  if(nearBottomRef.current)endRef.current?.scrollIntoView({block:'end'});
 },[active,selected?.messages?.length]);
 const counts={all:threads.length,open:threads.filter(x=>x.status==='open').length,
  answered:threads.filter(x=>x.status==='answered').length,closed:threads.filter(x=>x.status==='closed').length,
  unread:threads.filter(x=>(x.unread||0)>0).length,
  suspended:threads.filter(x=>isSuspended(x)).length};
 const visible=useMemo(()=>{
  const filtered=threads.filter(x=>
   (filter==='all'||(filter==='unread'?(x.unread||0)>0:filter==='suspended'?isSuspended(x):x.status===filter))&&
   (!query||[x.subject,x.name,x.username].some(v=>v?.toLowerCase().includes(query.toLowerCase()))));
  // Sin leer primero, luego por último mensaje.
  return [...filtered].sort((a,b)=>(((b.unread||0)>0)-((a.unread||0)>0))||
   (new Date(b.last_message_at).getTime()-new Date(a.last_message_at).getTime()));
 },[threads,filter,query]);
 async function mutate(body,opts={}){
  setBusy(true);setError('');setNotice('');
  try{
   const r=await fetch('/api/admin/support',{method:'POST',cache:'no-store',credentials:'same-origin',
    headers:{'Content-Type':'application/json','X-SPDecode-Admin-Action':'1'},body:JSON.stringify(body)});
   const data=await r.json().catch(()=>null);
   if(!r.ok)throw Error(errorText(data,r.status,'No se pudo guardar la operación.'));
   if(opts.clearDraft&&body.threadId){writeDraft(body.threadId,'');setAnswer('');}
   setNotice(opts.notice||'Conversación actualizada.');
   await load();
   if(body.action==='reply')markRead(body.threadId);
  }catch(e){
   setError(e instanceof TypeError?'No se pudo conectar con el servidor. Revisa tu conexión y reintenta.':
    (e.message||'No se pudo guardar la operación.'));
  }finally{setBusy(false);}
 }
 const reply=()=>{if(selected&&answer.trim())
  mutate({threadId:selected.id,action:'reply',message:answer.trim()},
   {clearDraft:true,notice:'Respuesta enviada.'});};
 const toggleClose=(confirmAlways=false)=>{
  if(!selected)return;
  if(selected.status!=='closed'){
   if(selected.unread>0&&!window.confirm('Este hilo tiene '+selected.unread+
    ' mensaje(s) sin leer. ¿Cerrar la conversación?'))return;
   if(confirmAlways&&!(selected.unread>0)&&!window.confirm('¿Cerrar esta conversación?'))return;
  }
  mutate({threadId:selected.id,action:selected.status==='closed'?'reopen':'close'});
 };
 const startRename=()=>{if(!selected)return;setTitleDraft(selected.subject||'');setEditingTitle(true);};
 const saveTitle=()=>{
  const subject=titleDraft.trim();
  if(subject.length<4||subject.length>100){setError('El título debe tener entre 4 y 100 caracteres.');return;}
  setEditingTitle(false);
  mutate({action:'rename',threadId:selected.id,subject},{notice:'Título actualizado.'});
 };
 const liftSuspension=()=>{
  if(!selected?.account_id)return;
  if(!window.confirm('¿Levantar la suspensión de soporte de esta cuenta?'))return;
  mutate({action:'liftSuspension',accountId:selected.account_id},{notice:'Suspensión levantada.'});
 };
 // Escalación a Pedro (D5): solo el agente asignado o quien puede asignar
 // (owner/admin). El hilo queda marcado y en prioridad alta.
 const canEscalate=!!(selected&&canWrite&&!selected.escalated_at&&
  (selected.assigned_staff_id===access?.id||access?.capabilities?.includes('support.assign')));
 const escalate=()=>{
  if(!selected||!canEscalate)return;
  if(!window.confirm('¿Escalar esta conversación a Pedro? La verá marcada y en prioridad alta.'))return;
  mutate({action:'escalate',threadId:selected.id},{notice:'Conversación escalada a Pedro.'});
 };
 const openThread=id=>{setActive(id);};
 const backToInbox=()=>{setActive('');};
 const navigateThread=dir=>{
  if(!visible.length)return;
  const i=visible.findIndex(t=>t.id===active);
  const next=visible[(i<0?(dir>0?0:visible.length-1):(i+dir+visible.length)%visible.length)];
  if(next)openThread(next.id);
 };
 useEffect(()=>{
  const focusSearch=()=>{
   if(active){backToInbox();setTimeout(()=>searchRef.current?.focus(),50);}
   else searchRef.current?.focus();
  };
  const onKey=e=>{
   const tag=e.target?.tagName;
   const editable=tag==='INPUT'||tag==='TEXTAREA'||tag==='SELECT'||e.target?.isContentEditable;
   if((e.ctrlKey||e.metaKey)&&e.key.toLowerCase()==='k'){e.preventDefault();focusSearch();return;}
   if(editable)return;
   if(e.key==='/'){e.preventDefault();focusSearch();}
   else if(e.key==='Escape'){if(editingTitle)setEditingTitle(false);else if(active)backToInbox();}
   else if(e.key==='j'||e.key==='k'){e.preventDefault();navigateThread(e.key==='j'?1:-1);}
   else if((e.key==='c'||e.key==='C')&&selected){toggleClose(true);}
  };
  window.addEventListener('keydown',onKey);
  return ()=>window.removeEventListener('keydown',onKey);
 });
 const suspendedSelected=selected?isSuspended(selected):false;
 const lastAuthor=m=>m?.sender==='admin'?(m.agent?.name||'Yamada')+': ':'Cliente: ';
 const retryLoad=()=>{setLoading(true);setLoadError('');load().catch(()=>{}).finally(()=>setLoading(false));};
 const inbox=<section className="sp-chat-inbox sp-chat-inbox-card" aria-label="Bandeja de conversaciones">
  <header><h2>Conversaciones</h2><small>{counts.all} en total{unreadTotal>0?' · '+unreadTotal+' sin leer':''}</small></header>
  <input ref={searchRef} className="sp-chat-search" value={query} onChange={e=>setQuery(e.target.value)}
   placeholder="Buscar conversación… ( / )" aria-label="Buscar conversaciones"/>
  <div className="sp-chat-filters">{Object.entries({all:['Todas',counts.all],unread:['Sin leer',counts.unread],
   open:['Pendientes',counts.open],answered:['Respondidas',counts.answered],closed:['Cerradas',counts.closed],
   suspended:['Suspendidos',counts.suspended]}).map(([key,[label,n]])=><button type="button" key={key}
   aria-pressed={filter===key} onClick={()=>setFilter(key)}>{label} <small>{n}</small></button>)}</div>
  <div className="sp-chat-inbox-scroll">
   {loading?<div className="sp-chat-loading" role="status"><span className="sp-chat-spinner" aria-hidden="true"/>
     <p>Cargando conversaciones…</p>
     <div className="sp-chat-skeleton" aria-hidden="true"><i/><i/><i/></div></div>
   :loadError?<div className="sp-chat-loading" role="alert"><p>{loadError}</p>
     <button type="button" className="button" onClick={retryLoad}>Reintentar</button></div>
   :visible.map(t=>{
    const last=t.messages?.[t.messages.length-1];
    const susp=isSuspended(t);
    return <button type="button" className={'sp-chat-thread '+((t.unread||0)>0?'unread ':'')+(active===t.id?'selected':'')}
     key={t.id} onClick={()=>openThread(t.id)}
     aria-label={(t.name||'Cuenta')+', '+STATUS[t.status]+((t.unread||0)>0?', '+t.unread+' sin leer':'')+(susp?', suspendido':'')}>
     <Initial name={t.name} src={t.avatar}/>
     <span className="sp-chat-thread-content">
      <span className="sp-chat-thread-title"><strong>{t.name||'Cuenta'}</strong>
       {(t.unread||0)>0&&<span className="sp-chat-unread-badge" aria-hidden="true">{t.unread>99?'99+':t.unread}</span>}
       <time>{fullDate(t.last_message_at)}</time></span>
      <span className="sp-chat-thread-subtitle">{t.subject}</span>
      <span className="sp-chat-preview">{last?lastAuthor(last)+last.text:(CATEGORY[t.category]||'Conversación')}</span>
      <span className="sp-chat-ticket-footer"><span className={'sp-chat-status '+t.status}>{STATUS[t.status]}</span>
       <span className="sp-chat-chip">{CATEGORY[t.category]||t.category||'General'}</span>
       <span className={'sp-chat-chip priority-'+(t.priority||'normal')}>{PRIORITY[t.priority||'normal']||'Normal'}</span>
       {t.escalated_at&&<span className="sp-chat-chip">Escalado a Pedro</span>}
       {susp&&<span className="sp-chat-suspended" title={suspensionDetail(t.suspension)}>{suspensionLabel(t.suspension)}</span>}
      </span>
     </span>
    </button>;
   })}
   {!loading&&!loadError&&!visible.length&&<p className="sp-chat-empty">No hay conversaciones para este filtro.</p>}
  </div>
  <p className="muted sp-chat-shortcuts">Atajos: / buscar · j/k cambiar de hilo · Esc volver · C cerrar o reabrir</p>
 </section>;
 return <div className="sp-admin-commerce sp-support-admin">
  {selected?<div className="sp-chat-fullscreen">
   <div className="sp-chat-fullscreen-top">
    <button type="button" className="button" onClick={backToInbox}>← Volver a la bandeja</button>
    <span className="muted">Mensajes de soporte</span>
    {unreadTotal>0&&<span className="sp-chat-unread-badge" aria-label={unreadTotal+' sin leer'}>{unreadTotal>99?'99+':unreadTotal}</span>}
   </div>
   {error&&<p className="form-message error" role="alert">{error}</p>}
   {notice&&<p className="form-message" role="status">{notice}</p>}
   {refreshError&&<p className="form-message" role="status">No se pudo actualizar. <button type="button" className="sp-chat-link-button" onClick={()=>load().catch(()=>{})}>Reintentar</button></p>}
   <section className="sp-chat-dialog sp-chat-dialog-full" aria-label="Conversación de soporte">
    <header className="sp-chat-dialog-header">
     <Initial name={selected.name} src={selected.avatar}/>
     <div><h2>{selected.name||'Cliente'}</h2>
      {editingTitle?<span className="sp-chat-rename">
       <input value={titleDraft} maxLength={100} onChange={e=>setTitleDraft(e.target.value)} aria-label="Título del hilo" autoFocus
        onKeyDown={e=>{if(e.key==='Enter'){e.preventDefault();saveTitle();}if(e.key==='Escape')setEditingTitle(false);}}/>
       <button type="button" className="button primary" disabled={busy||titleDraft.trim().length<4||titleDraft.trim().length>100} onClick={saveTitle}>Guardar</button>
       <button type="button" className="button" onClick={()=>setEditingTitle(false)}>Cancelar</button>
      </span>:
      <p>{selected.username?'@'+selected.username+' · ':''}{selected.subject} <button type="button" className="sp-chat-rename-btn" onClick={startRename} title="Editar título" aria-label="Editar título">✎</button></p>}
     </div>
     <span className={'sp-chat-status '+selected.status}>{STATUS[selected.status]}</span>
     <span className="sp-chat-chip">{CATEGORY[selected.category]||selected.category||'General'}</span>
     <span className={'sp-chat-chip priority-'+(selected.priority||'normal')}>{PRIORITY[selected.priority||'normal']||'Normal'}</span>
     {selected.assigned_name&&<span className="sp-chat-chip">{selected.assigned_name} · {selected.assignedOnline?'En línea':'Sin conexión'}</span>}
     {selected.escalated_at&&<span className="sp-chat-chip">Escalado a Pedro</span>}
     {suspendedSelected&&<button type="button" className="sp-chat-suspended" title={suspensionDetail(selected.suspension)}
       aria-label={suspensionDetail(selected.suspension)} onClick={()=>setShowSuspDetail(v=>!v)}>{suspensionLabel(selected.suspension)}</button>}
     {suspendedSelected&&canWrite&&<button type="button" className="button" disabled={busy} onClick={liftSuspension}>Levantar suspensión</button>}
     {selected.account_id&&<Link className="sp-chat-client-link" href={'/admin/users?q='+encodeURIComponent(selected.account_id)}>Ver cliente</Link>}
    </header>
    {suspendedSelected&&showSuspDetail&&<div className="sp-chat-suspension-detail" role="status">
     <span>{suspensionDetail(selected.suspension)}</span>
     <span>La suspensión solo bloquea al cliente: puedes seguir respondiendo.</span>
    </div>}
    <div className="sp-chat-message-scroller" ref={scrollerRef} role="log" aria-live="polite"
     onScroll={e=>{const el=e.currentTarget;nearBottomRef.current=el.scrollHeight-el.scrollTop-el.clientHeight<90;}}>
     {selected.messages?.map(m=>m.sender==='admin'?<div key={m.id} className="sp-chat-bubble-row outgoing">
      <div className="sp-chat-bubble outgoing">
       <strong><SenderLabel message={m} customLabels={customLabels}/></strong>
       <p>{m.text}</p><time>{new Date(m.at).toLocaleString('es-MX',{hour:'2-digit',minute:'2-digit'})}</time>
      </div>
      <span className="sp-chat-bubble-avatar"><Initial name={m.agent?.name||'Yamada'} src={m.agent?.avatar}/></span>
     </div>:<div key={m.id} className="sp-chat-bubble incoming">
      <strong><SenderLabel message={m} customLabels={customLabels}/></strong>
      <p>{m.text}</p><time>{new Date(m.at).toLocaleString('es-MX',{hour:'2-digit',minute:'2-digit'})}</time>
     </div>)}
     <div ref={endRef}/>
    </div>
    {selected.status!=='closed'?<div className="sp-chat-compose">
     <textarea value={answer} onChange={e=>{setAnswer(e.target.value);writeDraft(selected.id,e.target.value);}} maxLength={4000}
      rows={1} placeholder="Escribe un mensaje…" aria-label="Respuesta al cliente"
      onKeyDown={e=>{if(e.key==='Enter'&&(!e.shiftKey||e.ctrlKey||e.metaKey)){e.preventDefault();reply();}}}/>
     <button type="button" className="sp-chat-send" disabled={!answer.trim()||busy}
      aria-label="Enviar respuesta" title="Enviar respuesta" onClick={reply}>
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" width="21" height="21"
       aria-hidden="true"><path d="M22 2L11 13M22 2l-7 20-4-9-9-4z"/></svg>
     </button>
    </div>:<div className="sp-chat-closed">Conversación cerrada. Puedes reabrirla.</div>}
    {canWrite&&<footer className="sp-chat-footer">
     <button className="button" type="button" disabled={busy} onClick={()=>toggleClose(false)}>
      {selected.status==='closed'?'Reabrir conversación':'Cerrar conversación'}
     </button>
     {canEscalate&&<button className="button" type="button" disabled={busy} onClick={escalate}>
      Escalar a Pedro
     </button>}
    </footer>}
   </section>
   <p className="muted sp-chat-shortcuts">Atajos: / buscar · j/k cambiar de hilo · Esc volver a la bandeja · C cerrar o reabrir</p>
  </div>:<>
   <section className="sp-admin-commerce-hero"><div>
    <span className="sp-admin-commercial-kicker">ATENCIÓN AL CLIENTE</span>
    <h2>Centro de conversaciones</h2>
    <p>Responde y supervisa las solicitudes de soporte de forma segura.</p>
   </div><div className="sp-chat-hero-pills">
    {unreadTotal>0&&<span className="sp-support-pill sp-support-pill-unread">{unreadTotal} sin leer</span>}
    <span className="sp-support-pill">{counts.open} pendientes</span>
   </div></section>
   {error&&<p className="form-message error" role="alert">{error}</p>}
   {notice&&<p className="form-message" role="status">{notice}</p>}
   {refreshError&&<p className="form-message" role="status">No se pudo actualizar. <button type="button" className="sp-chat-link-button" onClick={()=>load().catch(()=>{})}>Reintentar</button></p>}
   {inbox}
  </>}
 </div>;
}
