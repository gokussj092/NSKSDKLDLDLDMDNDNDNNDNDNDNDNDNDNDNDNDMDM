"use client";
import {useCallback,useEffect,useRef,useState} from "react";
import {useRouter} from "next/navigation";

const samples=[
 {name:"Mensaje personalizado",title:"",body:""},
 {name:"Actualización",title:"SP-DECODE · Actualización disponible",body:"Hay una nueva actualización de SP-DECODE. Consulta el canal oficial para conocer los detalles."},
 {name:"Mantenimiento",title:"SP-DECODE · Mantenimiento",body:"Estamos realizando tareas de mantenimiento. Algunas funciones pueden no estar disponibles temporalmente."},
 {name:"Catálogo VPN",title:"SP-DECODE · Catálogo actualizado",body:"Ya puedes comprobar si hay nuevas versiones del catálogo Server VPN desde la aplicación."}
];
const action=body=>({method:"POST",cache:"no-store",credentials:"same-origin",
 headers:{"Content-Type":"application/json","X-SPDecode-Admin-Action":"1"},body:JSON.stringify(body)});
const time=t=>Number.isSafeInteger(t)?new Date(t).toLocaleString("es-MX",{dateStyle:"medium",timeStyle:"short"}):"Sin fecha";
export default function AdminNotifications(){
 const [title,setTitle]=useState(""),[body,setBody]=useState("");
 const [busy,setBusy]=useState(false),[result,setResult]=useState("");
 const [list,setList]=useState([]),[loading,setLoading]=useState(true);
 const [pushConfigured,setPushConfigured]=useState(false);
 const pending=useRef(null),router=useRouter();
 const refresh=useCallback(async()=>{
  try{
   const r=await fetch("/api/admin/notifications",{credentials:"same-origin",cache:"no-store"});
   if(r.status===401){router.replace("/admin/login");return;}
   if(!r.ok)throw Error("No se pudo cargar el historial de avisos ("+r.status+").");
   const data=await r.json();if(!Array.isArray(data.notices))throw Error("El historial recibido no es válido.");
   setList(data.notices.slice().sort((a,b)=>b.createdAt-a.createdAt));
   setPushConfigured(Boolean(data.pushConfigured));setResult("");
  }catch(e){setResult(e.message||"No se pudo consultar el historial.");}
  finally{setLoading(false);}
 },[router]);
 useEffect(()=>{refresh();},[refresh]);
 function editTitle(v){setTitle(v);pending.current=null;}
 function editBody(v){setBody(v);pending.current=null;}
 function useTemplate(i){
  const selected=samples[i];if(!selected)return;
  setTitle(selected.title);setBody(selected.body);pending.current=null;setResult("");
 }
 async function publish(e){
  e.preventDefault();if(busy||!title.trim()||!body.trim())return;
  const t=title.trim(),message=body.trim();
  if(t.length>80||message.length>500)return;
  if(!window.confirm("¿Publicar este aviso a los dispositivos suscritos? Caducará en 7 días y no es posible editarlo después."))return;
  setBusy(true);setResult("");
  if(!pending.current)pending.current=crypto.randomUUID();
  try{
   const r=await fetch("/api/admin/notifications",action({id:pending.current,title:t,body:message}));
   if(r.status===401){router.replace("/admin/login");return;}
   const data=await r.json();
   if(!r.ok)throw Error("No se pudo publicar el aviso ("+r.status+").");
   setResult(data.status==="already-published"?"El aviso ya estaba registrado: no se ha duplicado.":
    data.delivery==="push"?"Aviso guardado; FCM recibió la señal de entrega.":"Aviso publicado. Los dispositivos lo consultarán al conectarse.");
   editTitle("");editBody("");pending.current=null;
   await refresh();setResult(data.delivery==="push"?"Aviso publicado. FCM aceptó la señal; la recepción en cada dispositivo no está garantizada.":
    "Aviso publicado y guardado. La entrega se realizará en la próxima comprobación de Android.");
  }catch(e){setResult(e.message||"No se pudo publicar. Puedes reintentar sin crear duplicados.");}
  finally{setBusy(false);}
 }
 async function verifyPush(){
  if(busy)return;
  setBusy(true);setResult("");
  try{
   const r=await fetch("/api/admin/notifications/verify-fcm",action({}));
   if(r.status===401){router.replace("/admin/login");return;}
   if(!r.ok)throw Error("FCM no pudo validarse ("+r.status+").");
   setResult("FCM validado sin enviar avisos reales. Esto no demuestra recepción en los dispositivos.");
  }catch(e){setResult(e.message||"No se pudo verificar FCM.");}
  finally{setBusy(false);}
 }
 return <div className="sp-admin-notice-page">
  <div className="admin-grid">
   <section className="admin-card">
    <h2>Redactar una notificación</h2>
    <p className="muted">Los avisos se muestran a quienes autorizaron notificaciones. No incluyas contraseñas, claves privadas ni información sensible.</p>
    <div className="sp-admin-notice-templates" role="group" aria-label="Plantillas de notificaciones">
     {samples.map((s,i)=><button key={s.name} type="button" className="button subtle" onClick={()=>useTemplate(i)}
      disabled={busy}>{s.name}</button>)}
    </div>
    <form onSubmit={publish} className="admin-form sp-admin-notice-form">
     <label>Título <span className="sp-admin-notice-count">{title.length}/80</span>
      <input required maxLength={80} value={title} onChange={e=>editTitle(e.target.value)}
       placeholder="Ejemplo: Actualización de SP-DECODE" disabled={busy}/>
     </label>
     <label>Contenido <span className="sp-admin-notice-count">{body.length}/500</span>
      <textarea required rows={7} maxLength={500} value={body} onChange={e=>editBody(e.target.value)}
       placeholder="Escribe un mensaje claro y preciso para los usuarios…" disabled={busy}/>
     </label>
     <div className="sp-admin-notice-actions">
      <button className="button primary" type="submit" disabled={busy||!title.trim()||!body.trim()}>
       {busy?"Publicando…":"Confirmar y publicar aviso"}</button>
      <button type="button" className="button subtle" disabled={busy} onClick={()=>{editTitle("");editBody("");setResult("");}}>Limpiar</button>
     </div>
    </form>
   </section>
   <section className="admin-card">
    <h2>Vista previa en Android</h2>
    <p className="muted">La apariencia final depende de la versión del sistema, permisos y ajustes del usuario.</p>
    <div className="sp-admin-notice-preview" aria-label="Vista previa del aviso" role="status">
      <div className="sp-admin-notice-preview-app"><span className="sp-admin-notice-preview-mark">SP</span><strong>SP-DECODE</strong><small>Ahora</small></div>
      <strong>{title.trim()||"Título de la notificación"}</strong>
      <p>{body.trim()||"El mensaje se mostrará aquí mientras escribes."}</p>
    </div>
    <div className="admin-kv"><span>Estado de FCM</span><strong>{loading?"Consultando…":pushConfigured?"Configurado":"No configurado"}</strong></div>
    <div className="admin-kv"><span>Caducidad</span><strong>7 días</strong></div>
    <button type="button" className="button subtle" onClick={verifyPush} disabled={busy}>Validar conexión FCM sin enviar</button>
    <p className="muted">FCM puede despertar la comprobación de avisos, pero no garantiza que todos los dispositivos reciban un aviso inmediatamente.</p>
   </section>
  </div>
  {result&&<p role="status" className="sp-admin-notice-result">{result}</p>}
  <section className="admin-card sp-admin-notice-history">
   <div className="sp-admin-section-heading"><div><h2>Notificaciones publicadas</h2>
    <p className="muted">Últimos avisos persistidos en el servidor. Su publicación y recepción son eventos distintos.</p></div>
    <button type="button" className="button subtle" disabled={busy||loading} onClick={refresh}>Actualizar</button>
   </div>
   {loading?<p className="muted">Cargando avisos…</p>:
    list.length===0?<p className="muted">No hay avisos publicados vigentes.</p>:
    <div className="sp-admin-notice-list">{list.map(n=><article className="sp-admin-notice-history-row" key={n.id}>
      <div><strong>{n.title}</strong><p>{n.body}</p></div>
      <small>Publicado: {time(n.createdAt)}<br/>Caduca: {time(n.expiresAt)}</small>
    </article>)}</div>}
  </section>
 </div>;
}
