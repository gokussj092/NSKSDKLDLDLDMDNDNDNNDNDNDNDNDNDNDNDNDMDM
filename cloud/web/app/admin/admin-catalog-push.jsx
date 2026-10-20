"use client";
import {useEffect,useState} from "react";
import {useRouter} from "next/navigation";
export default function AdminCatalogPush(){
 const [data,setData]=useState(null),[busy,setBusy]=useState(false),[error,setError]=useState(""),[done,setDone]=useState("");
 const router=useRouter();
 async function refresh(){
  try{
   const r=await fetch("/api/admin/catalog-push",{credentials:"same-origin",cache:"no-store"});
   if(r.status===401){router.replace("/admin/login");return;}
   if(!r.ok)throw Error("No se pudo consultar el estado de las notificaciones.");
   setData(await r.json());setError("");
  }catch(e){setError(e.message);}
 }
 useEffect(()=>{refresh();},[]);
 async function announce(){
  if(busy||!data?.configured)return;
  if(!window.confirm("¿Publicar un aviso con la versión del catálogo configurada en el servidor? Los dispositivos suscritos verificarán la versión antes de descargar datos."))return;
  setBusy(true);setError("");setDone("");
  try{
   const response=await fetch("/api/admin/catalog-push",{method:"POST",credentials:"same-origin",cache:"no-store",
    headers:{"X-SPDecode-Admin-Action":"1","Content-Type":"application/json"},body:""});
   const result=await response.json();
   if(!response.ok)throw Error("No se pudo enviar el aviso ("+response.status+").");
   setDone(result.status==="registered"?"Versión registrada en la VPS. Los clientes conectados comprobarán la versión; la entrega a dispositivos cerrados no es inmediata.":
      result.status==="unchanged"?"La versión ya fue anunciada.": "Hay otro envío en curso.");
   await refresh();
  }catch(e){setError(e.message||"No se pudo publicar.");}
  finally{setBusy(false);}
 }
 return <section className="admin-card admin-report-card">
  <div className="sp-admin-section-heading"><div>
   <h2>Actualizaciones del catálogo Server VPN</h2>
   <p className="muted">La VPS atiende avisos de versión mediante HTTPS cuando Android está activa. Las tareas de recuperación comprueban cambios sin conexión persistente.</p>
  </div></div>
  <div className="admin-kv"><span>Avisos HTTPS de la VPS</span><strong>{data?.configured?"Configurado":"Sin configurar"}</strong></div>
  <div className="admin-kv"><span>Última versión anunciada</span><strong>{data?.lastAnnounced||"—"}</strong></div>
  <p className="muted">Los cambios son visibles automáticamente al aumentar CLOUD_SERVER_VPN_CATALOG_VERSION y desplegar el catálogo. Este botón registra la versión actual para auditoría; no modifica los datos ni contacta con servicios externos.</p>
  <button className="button subtle" onClick={announce} disabled={busy||!data?.configured}> {busy?"Publicando…":"Registrar versión disponible"} </button>
  {error&&<p className="form-message error" role="alert">{error}</p>}
  {done&&<p role="status" className="muted">{done}</p>}
 </section>;
}
