"use client";
import {useCallback,useEffect,useState} from "react";
import {useRouter} from "next/navigation";
const requestOptions=body=>({method:"POST",cache:"no-store",credentials:"same-origin",
 headers:{"Content-Type":"application/json","X-SPDecode-Admin-Action":"1"},body:JSON.stringify(body)});
const serviceList=[
 ["files","Archivos y textos","Solicitudes a motores de archivos y texto"],
 ["httpInjector","HTTP Injector Cloud","Importación de configuraciones EHI Cloud"],
 ["serverVpn","Server VPN","Descifrado de catálogos remotos de servidores VPN"],
];
const fmt=new Intl.NumberFormat("es-MX");
function Health({ok}){return <span className="sp-admin-health" data-ok={ok?"yes":"no"}><span aria-hidden="true"/> {ok?"Disponible":"No disponible"}</span>}
export default function AdminDashboard(){
 const [data,setData]=useState(null),[busy,setBusy]=useState(false);
 const [error,setError]=useState(""),[loading,setLoading]=useState(true);
 const router=useRouter();
 const refresh=useCallback(async()=>{
  try{
   const response=await fetch("/api/admin/session",{cache:"no-store",credentials:"same-origin"});
   if(response.status===401){router.replace("/admin/login");return;}
   if(!response.ok)throw Error("No se pudo consultar el estado administrativo.");
   const json=await response.json();setData(json);setError("");
  }catch(err){setError(err.message||"No se pudo obtener el estado.");}
  finally{setLoading(false);}
 },[router]);
 useEffect(()=>{refresh();},[refresh]);
 async function changeMaintenance(service){
  if(!data||busy||data.maintenanceLocked)return;
  const global=service===null;
  const previous=global?data.maintenance:data.serviceMaintenance?.[service];
  const enabled=!previous;
  const name=global?"mantenimiento general":serviceList.find(x=>x[0]===service)?.[1];
  if(!window.confirm("¿"+(enabled?"Activar":"Desactivar")+" "+name+"? "+(enabled?"Se rechazarán nuevas operaciones de este servicio.":"Se reanudarán las operaciones si la infraestructura está disponible.")))return;
  setBusy(true);setError("");
  try{
   const response=await fetch("/api/admin/maintenance",requestOptions(global?{enabled}:{enabled,service}));
   if(!response.ok)throw Error("El servidor rechazó el cambio ("+response.status+").");
   await refresh();
  }catch(e){setError(e.message||"No se pudo cambiar el estado.");}
  finally{setBusy(false);}
 }
 async function changeProvider(id,enabled,name){
  if(!data?.providerControls||busy)return;
  const action=enabled?"Activar":"Desactivar";
  const warning=enabled?
   "El servidor utilizará la integración únicamente si están configurados los requisitos privados en la VPS.":
   "Los nuevos descifrados de este proveedor quedarán deshabilitados.";
  if(!window.confirm("¿"+action+" "+name+"? "+warning))return;
  setBusy(true);setError("");
  try{
   const response=await fetch("/api/admin/providers",requestOptions({id,enabled}));
   const result=await response.json();
   if(!response.ok)throw Error(response.status===409?
    "El proveedor está bloqueado o no tiene configurados los requisitos de VPS.":
    "No se pudo guardar el cambio ("+response.status+").");
   setData(prev=>({...prev,providerControls:result.providerControls}));
   await refresh();
  }catch(e){setError(e.message||"No se pudo actualizar el proveedor.");}
  finally{setBusy(false);}
 }
 async function changePlayAdmission(){
  if(!data?.playAdmission||busy||data.playAdmission.locked)return;
  const required=!data.playAdmission.integrityRequired;
  const prompt=required?
   "¿Exigir Google Play Integrity nuevamente? Las APK instaladas fuera de Play dejarán de obtener sesiones Cloud nuevas.":
   "¿Activar durante un máximo de 15 días el acceso beta sin Play Integrity? Cualquier cliente podrá intentar solicitar una sesión; se conservarán los límites de uso. Se cerrará automáticamente al vencer.";
  if(!window.confirm(prompt))return;
  setBusy(true);setError("");
  try{
   const response=await fetch("/api/admin/play-admission",requestOptions({integrityRequired:required}));
   if(!response.ok)throw Error("No se pudo cambiar la política ("+response.status+").");
   await refresh();
  }catch(e){setError(e.message||"No se pudo actualizar la política.");}
  finally{setBusy(false);}
 }
 async function logout(){
  setBusy(true);
  try{
   const response=await fetch("/api/admin/logout",requestOptions({}));
   if(!response.ok)throw Error("No se pudo cerrar la sesión.");
   router.replace("/admin/login");router.refresh();
  }catch(e){setError(e.message);}finally{setBusy(false);}
 }
 if(loading)return <div className="admin-card" role="status">Consultando el estado del servidor…</div>;
 return <section className="sp-admin-dashboard">
  {error&&<div className="form-message error" role="alert">{error}</div>}
  {data&&<>
   <div className="admin-metric-grid">
    <article className="admin-card"><span className="muted">Correctos hoy · UTC</span><strong>{fmt.format(data.metrics.successfulDecodes)}</strong><small className="muted">Descifrados del worker</small></article>
    <article className="admin-card"><span className="muted">Fallidos hoy · UTC</span><strong>{fmt.format(data.metrics.failedDecodes)}</strong><small className="muted">Resultado del worker</small></article>
    <article className="admin-card"><span className="muted">Operaciones procesadas</span><strong>{fmt.format(data.metrics.successfulDecodes+data.metrics.failedDecodes)}</strong><small className="muted">No equivale a usuarios únicos</small></article>
    <article className="admin-card"><span className="muted">Estado general</span><strong className="sp-admin-status-text">{data.maintenance?"Mantenimiento":"Operativo"}</strong><small className="muted">Control global</small></article>
   </div>
   <div className="admin-grid">
    <section className="admin-card">
     <h2>Infraestructura</h2>
     {[
      ["API configurada",data.services.apiConfigured],
      ["Redis",data.services.redisConnected],
      ["Worker privado",data.services.workerReady],
      ["HTTP Injector Cloud",data.services.ehiImportConfigured],
      ["Catálogo de Servidores VPN",data.services.nurCatalogImportConfigured]
     ].map(([title,ok])=><div className="admin-kv" key={title}><span>{title}</span><Health ok={ok}/></div>)}
    </section>
    <section className="admin-card">
     <h2>Control general</h2>
     <p className="muted">El mantenimiento general tiene prioridad sobre todos los servicios. Las operaciones ya iniciadas pueden finalizar.</p>
     <div className="sp-admin-switch-row">
      <div><strong>Mantenimiento global</strong><small className="muted">{data.maintenanceLocked?"Bloqueado por configuración del VPS":data.maintenance?"Todas las nuevas solicitudes se rechazan":"Sin bloqueo general"}</small></div>
      <button className="sp-admin-switch" role="switch" aria-label="Mantenimiento global" aria-checked={data.maintenance} disabled={busy||data.maintenanceLocked} onClick={()=>changeMaintenance(null)}><span/></button>
     </div>
     {data.maintenanceLocked&&<p className="muted sp-admin-status-note">
      El bloqueo procede de la VPS y no puede anularse desde el navegador.
      En la terminal ejecuta <code>sudo spdecode config set CLOUD_FORCE_MAINTENANCE false</code>
      y después <code>sudo spdecode restart web</code>. Recarga el panel para
      desactivar el mantenimiento global si el interruptor continúa encendido.
     </p>}
    </section>
   </div>
   <section className="admin-card sp-admin-services">
    <div className="sp-admin-section-heading"><div><h2>Distribución beta y Google Play Integrity</h2>
     <p className="muted">Esta política afecta a nuevas sesiones Cloud, no a la firma local ni a la seguridad de Google Play.</p></div></div>
    <div className="sp-admin-switch-row">
     <div><strong>Exigir verificación de Google Play</strong>
      <small className="muted">{data.playAdmission?.integrityRequired?
       "Activa: se requiere una instalación reconocida y el veredicto de Play Integrity.":
       "Modo beta temporal: la verificación de Play está pausada, con límites de uso."}</small>
      <small className="sp-admin-status-note">{data.playAdmission?.betaUntil?
       "Caducidad automática (UTC): "+new Date(data.playAdmission.betaUntil).toLocaleString("es-MX",{timeZone:"UTC"}):
       data.playAdmission?.locked?"Control beta deshabilitado desde el VPS":"Acceso estándar protegido"}</small></div>
     <button role="switch" className="sp-admin-switch" aria-label="Exigir Google Play Integrity"
      aria-checked={data.playAdmission?.integrityRequired??true}
      disabled={busy||data.playAdmission?.locked} onClick={changePlayAdmission}><span/></button>
    </div>
    <p className="muted">No utilices este modo como protección contra aplicaciones alteradas: durante la beta no hay autenticación criptográfica del origen del cliente. Se restablece automáticamente después de 15 días; puedes desactivarlo antes.</p>
   </section>
   <section className="admin-card sp-admin-services">
    <div className="sp-admin-section-heading"><div>
     <h2>Disponibilidad de importaciones remotas</h2>
     <p className="muted">Activa o desactiva HTTP Injector Cloud, el catálogo Servidores VPN y cada proveedor individual. Estos controles no requieren QA. El servidor debe tener habilitados previamente los requisitos privados de cada integración.</p>
    </div><span className="sp-admin-chip">Servicios Cloud</span></div>
    <div className="admin-kv"><span>Versión del catálogo Server VPN</span><strong>{data.providerControls?.catalogVersion??"—"}</strong></div>
    {(data.providerControls?.providers||[]).map(provider=>{
     const locked=busy||!provider.configured||data.maintenance||data.maintenanceLocked;
     return <div className="sp-admin-switch-row" key={provider.id}>
      <div><strong>{provider.name}</strong>
       <small className="muted">{!provider.configured?"No configurado en la VPS":provider.enabled?"Habilitado para nuevos descifrados":"Deshabilitado desde el panel"}</small>
      </div>
      <button type="button" className="sp-admin-switch" role="switch"
       aria-label={"Disponibilidad: "+provider.name} aria-checked={Boolean(provider.enabled)}
       disabled={locked} onClick={()=>changeProvider(provider.id,!provider.enabled,provider.name)}><span/></button>
     </div>;
    })}
    <p className="muted">Los cambios se guardan en un volumen de configuración independiente, incluso al reiniciar Redis o los contenedores. La versión del catálogo aumenta cuando cambias un proveedor; actualiza Server VPN en la aplicación. La activación de HTTP Injector requiere las claves originales del proveedor, que no se muestran aquí.</p>
   </section>
   <section className="admin-card sp-admin-services">
    <div className="sp-admin-section-heading">
     <div><h2>Mantenimiento por servicio</h2><p className="muted">Puedes pausar un servicio sin detener los demás. La protección general siempre prevalece.</p></div>
     <span className="sp-admin-chip">Controles de API</span>
    </div>
    {serviceList.map(([id,title,description])=>{
     const offline=Boolean(data.serviceMaintenance?.[id]);
     const locked=busy||data.maintenanceLocked||data.maintenance;
     return <div className="sp-admin-switch-row" key={id}>
      <div><strong>{title}</strong><small className="muted">{description}</small>
       <small className="sp-admin-status-note">{data.maintenance?"Pausado por mantenimiento general":offline?"En mantenimiento":"Disponible para solicitudes nuevas"}</small></div>
      <button className="sp-admin-switch" role="switch" aria-label={"Mantenimiento: "+title} aria-checked={offline} disabled={locked} onClick={()=>changeMaintenance(id)}><span/></button>
     </div>;
    })}
    <p className="muted">Los estados se guardan en Redis. Las protecciones impuestas desde el VPS no se pueden anular aquí.</p>
   </section>
  </>}
  <div className="admin-actions">
   <button className="button subtle" onClick={()=>refresh()} disabled={busy} type="button">Actualizar estado</button>
   <button className="button subtle" onClick={logout} disabled={busy} type="button">Cerrar sesión</button>
  </div>
 </section>;
}
