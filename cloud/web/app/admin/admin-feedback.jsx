"use client";
import {useCallback,useEffect,useState} from "react";
import {useRouter} from "next/navigation";
const categories={method:"Nuevo método APK",bug:"Reporte de error",suggestion:"Sugerencia"};
const states={new:"Nuevo",reviewing:"En revisión",in_progress:"En proceso",resolved:"Resuelto",rejected:"No procede",archived:"Archivado"};
const priorities={low:"Baja",normal:"Normal",high:"Alta"};
const issues={decode_failed:"Falló el descifrado",catalog_download:"Error al descargar el catálogo",
 import_failed:"Fallo al importar",export_failed:"Fallo al exportar / unlocked",
 app_crash:"Cierre inesperado",cloud_access:"Error de acceso Cloud",other:"Otro error"};
const action=body=>({method:"POST",cache:"no-store",credentials:"same-origin",
 headers:{"Content-Type":"application/json","X-SPDecode-Admin-Action":"1"},body:JSON.stringify(body)});
const date=v=>{const n=Date.parse(v||"");return Number.isFinite(n)?
 new Date(n).toLocaleString("es-MX",{dateStyle:"medium",timeStyle:"short"}):"Sin fecha";};
const cleanLink=s=>{try{const u=new URL(s);return ["http:","https:"].includes(u.protocol)&&
 !u.username&&!u.password&&u.hostname.includes(".")&&!u.hash;}catch{return false;}};
const original=i=>({status:i.status,priority:i.priority,note:i.operatorNote||""});
export default function AdminFeedback(){
 const router=useRouter();
 const [category,setCategory]=useState("all"),[status,setStatus]=useState("all");
 const [priority,setPriority]=useState("all"),[page,setPage]=useState(0);
 const [data,setData]=useState(null),[loading,setLoading]=useState(true);
 const [busy,setBusy]=useState(false),[error,setError]=useState(""),[message,setMessage]=useState("");
 const [selectedId,setSelectedId]=useState(null),[draft,setDraft]=useState(null);
 const refresh=useCallback(async()=>{
  try{
   const q=new URLSearchParams({category,status,priority,page:String(page)});
   const r=await fetch("/api/admin/feedback?"+q,{credentials:"same-origin",cache:"no-store"});
   if(r.status===401){router.replace("/admin/login");return;}
   if(!r.ok)throw Error("No se pudo consultar la bandeja ("+r.status+").");
   const body=await r.json();
   if(!Array.isArray(body.feedback?.items))throw Error("Respuesta administrativa no válida.");
   setData(body.feedback);setError("");
   if(page>0 && page>=Math.max(1,body.feedback.pages))setPage(Math.max(0,body.feedback.pages-1));
  }catch(e){setError(e.message||"No se pudo cargar la bandeja.");}
  finally{setLoading(false);}
 },[router,category,status,priority,page]);
 useEffect(()=>{refresh();},[refresh]);
 function changeFilter(setter,value){
  setter(value);setPage(0);setSelectedId(null);setDraft(null);setMessage("");
 }
 function toggle(item){
  if(selectedId===item.id){setSelectedId(null);setDraft(null);}
  else{setSelectedId(item.id);setDraft(original(item));}
  setError("");setMessage("");
 }
 const selected=(data?.items||[]).find(x=>x.id===selectedId);
 const dirty=selected&&draft&&(draft.status!==selected.status||
  draft.priority!==selected.priority||draft.note!==(selected.operatorNote||""));
 async function save(e){
  e.preventDefault();if(busy||!selected||!draft||!dirty||draft.note.length>600)return;
  if(["resolved","rejected","archived"].includes(draft.status)&&
   draft.status!==selected.status&&!window.confirm("¿Confirmar «"+states[draft.status]+"» para esta solicitud?"))return;
  setBusy(true);setError("");setMessage("");
  try{
   const r=await fetch("/api/admin/feedback",action({
    id:selected.id,expectedRevision:selected.revision,status:draft.status,
    priority:draft.priority,note:draft.note,
   }));
   if(r.status===401){router.replace("/admin/login");return;}
   const body=await r.json();
   if([404,409].includes(r.status)){
    setSelectedId(null);setDraft(null);await refresh();
    throw Error(r.status===409?"La solicitud cambió en otra sesión. Revisa el estado actualizado.":
     "La solicitud ya no existe o ha caducado.");
   }
   if(!r.ok||!body.record)throw Error("No se guardó el seguimiento ("+r.status+").");
   const saved=body.record;setDraft(original(saved));
   await refresh();setMessage("Seguimiento interno guardado: "+saved.id);
  }catch(e){setError(e.message||"No se guardaron los cambios; puedes reintentar.");}
  finally{setBusy(false);}
 }
 if(loading)return <div className="admin-card" role="status">Cargando solicitudes…</div>;
 return <div className="sp-admin-feedback">
  <section className="admin-card">
   <h2>Bandeja de solicitudes</h2>
   <p className="muted">Solicitudes voluntarias de SP-DECODE. Los enlaces no se abren, descargan ni analizan automáticamente. Las notas internas no se envían al usuario.</p>
   {data&&<div className="sp-feedback-summary">
    <div><strong>{data.totals.available}</strong><span>Vigentes</span></div>
    <div><strong>{data.totals.new}</strong><span>Nuevas</span></div>
    <div><strong>{data.totals.reviewing+data.totals.in_progress}</strong><span>En atención</span></div>
    <div><strong>{data.totals.resolved}</strong><span>Resueltas</span></div>
   </div>}
   <div className="sp-feedback-filters">
    <label>Tipo
     <select value={category} onChange={e=>changeFilter(setCategory,e.target.value)}>
      <option value="all">Todos</option>
      {Object.entries(categories).map(([k,v])=><option key={k} value={k}>{v}</option>)}
     </select>
    </label>
    <label>Estado
     <select value={status} onChange={e=>changeFilter(setStatus,e.target.value)}>
      <option value="all">Todos</option>
      {Object.entries(states).map(([k,v])=><option key={k} value={k}>{v}</option>)}
     </select>
    </label>
    <label>Prioridad
     <select value={priority} onChange={e=>changeFilter(setPriority,e.target.value)}>
      <option value="all">Todas</option>
      {Object.entries(priorities).map(([k,v])=><option key={k} value={k}>{v}</option>)}
     </select>
    </label>
   </div>
   <div className="sp-feedback-toolbar">
    <span className="muted">{data?(String(data.total)+" resultados · página "+(page+1)+" de "+Math.max(1,data.pages)):"Sin datos"}</span>
    <button className="button subtle" type="button" disabled={busy} onClick={()=>refresh()}>Actualizar bandeja</button>
   </div>
  </section>
  {error&&<div className="form-message error" role="alert">{error}</div>}
  {message&&<div className="sp-admin-notice-result" role="status">{message}</div>}
  <div className="sp-feedback-list">
   {!data?.items.length&&<section className="admin-card"><p className="muted">Sin solicitudes para los filtros seleccionados.</p></section>}
   {(data?.items||[]).map(item=>{
    const open=selectedId===item.id;
    return <article className="admin-card sp-feedback-row" key={item.id}>
     <button type="button" className="sp-feedback-opener" onClick={()=>toggle(item)}
      aria-expanded={open} aria-controls={"feedback-detail-"+item.id} disabled={busy}>
      <span><strong>{categories[item.category]}</strong><small>{states[item.status]} · Prioridad {priorities[item.priority]}</small></span>
      <span className="muted">{date(item.receivedAt)}</span>
      <span aria-hidden="true">{open?"−":"+"}</span>
     </button>
     <div className="sp-feedback-id">Referencia: <code>{item.id}</code></div>
     {open&&<div id={"feedback-detail-"+item.id} className="sp-feedback-detail">
      <p className="muted">SP-DECODE {item.appVersion} · build {item.appBuild} · Revisión {item.revision} · Último cambio: {item.updatedAt?date(item.updatedAt):"Sin revisar"}</p>
      {item.category==="method"&&<div className="sp-feedback-field">
       <strong>Enlace de aplicación (fuente externa no verificada)</strong>
       {cleanLink(item.appLink)?<a href={item.appLink} target="_blank"
        rel="noopener noreferrer" referrerPolicy="no-referrer">{item.appLink}</a>:<span>Enlace no válido</span>}
      </div>}
      {!!item.issues?.length&&<div className="sp-feedback-field">
       <strong>Errores marcados</strong>
       <ul>{item.issues.map((v,i)=><li key={i}>{issues[v]||"Otro error"}</li>)}</ul>
      </div>}
      <div className="sp-feedback-field">
       <strong>{item.category==="bug"?"Informe adicional (opcional)":"Descripción del usuario"}</strong>
       <p>{item.description||"Sin descripción adicional"}</p>
      </div>
      <form className="sp-feedback-review-form" onSubmit={save}>
       <label>Estado<select value={draft?.status||item.status} disabled={busy}
        onChange={e=>setDraft(d=>({...d,status:e.target.value}))}>
        {Object.entries(states).map(([k,v])=><option key={k} value={k}>{v}</option>)}
       </select></label>
       <label>Prioridad<select value={draft?.priority||item.priority} disabled={busy}
        onChange={e=>setDraft(d=>({...d,priority:e.target.value}))}>
        {Object.entries(priorities).map(([k,v])=><option key={k} value={k}>{v}</option>)}
       </select></label>
       <label className="sp-feedback-note">Nota interna (máximo 600 caracteres)
        <textarea value={draft?.note||""} disabled={busy} rows={3} maxLength={600}
         onChange={e=>setDraft(d=>({...d,note:e.target.value}))}
         placeholder="Diagnóstico, seguimiento o resolución…"/>
       </label>
       <div className="sp-feedback-actions">
        <button className="button primary" type="submit" disabled={busy||!dirty}>{busy?"Guardando…":"Guardar seguimiento"}</button>
        <button className="button subtle" type="button" disabled={busy||!dirty}
         onClick={()=>setDraft(original(item))}>Descartar cambios</button>
       </div>
      </form>
     </div>}
    </article>;
   })}
  </div>
  <div className="sp-feedback-pagination">
   <button className="button subtle" disabled={busy||page===0} onClick={()=>{
    setPage(p=>p-1);setSelectedId(null);setDraft(null);}}>Anterior</button>
   <span>Página {page+1} / {Math.max(1,data?.pages||0)}</span>
   <button className="button subtle" disabled={busy||page+1>=Math.max(1,data?.pages||0)} onClick={()=>{
    setPage(p=>p+1);setSelectedId(null);setDraft(null);}}>Siguiente</button>
  </div>
  <p className="muted sp-feedback-retention">Retención original: 90 días por solicitud. Límite de la cola: 500 IDs. Archivar no prolonga la retención ni elimina la solicitud inmediatamente.</p>
 </div>;
}
