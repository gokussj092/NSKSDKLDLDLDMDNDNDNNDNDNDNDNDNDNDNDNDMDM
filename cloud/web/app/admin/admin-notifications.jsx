"use client";
import {useState} from "react";
export default function AdminNotifications(){
 const [title,setTitle]=useState(""),[body,setBody]=useState(""),[busy,setBusy]=useState(false),[result,setResult]=useState("");
 const [id,setId]=useState(null);
 async function publish(e){e.preventDefault();if(busy)return;setBusy(true);setResult("");
  const key=id||crypto.randomUUID();setId(key);
  try{
   const r=await fetch("/api/admin/notifications",{method:"POST",credentials:"same-origin",cache:"no-store",
    headers:{"Content-Type":"application/json","X-SPDecode-Admin-Action":"1"},body:JSON.stringify({id:key,title:title.trim(),body:body.trim()})});
   const data=await r.json();if(!r.ok)throw Error("No se pudo publicar ("+r.status+").");
   setResult(data.delivery==="push"?"Aviso publicado; señal push enviada.":"Aviso publicado. Se entregará durante la próxima comprobación de Android; la entrega no es inmediata.");
   setTitle("");setBody("");setId(null);
  }catch(e){setResult(e.message);}finally{setBusy(false);}
 }
 return <section className="admin-card"><h2>Notificaciones de la aplicación</h2>
  <p className="muted">Avisos de texto para usuarios que hayan activado las notificaciones. Caducan en 7 días. No incluyas contraseñas ni información privada.</p>
  <form onSubmit={publish} className="admin-form">
   <label>Título<input required maxLength={80} value={title} disabled={busy} onChange={e=>{setTitle(e.target.value);setId(null);}}/></label>
   <label>Mensaje<textarea required maxLength={500} value={body} disabled={busy} onChange={e=>{setBody(e.target.value);setId(null);}}/></label>
   <button className="button subtle" disabled={busy||!title.trim()||!body.trim()}>{busy?"Publicando…":"Publicar aviso"}</button>
  </form>{result&&<p role="status" className="muted">{result}</p>}
 </section>;
}
