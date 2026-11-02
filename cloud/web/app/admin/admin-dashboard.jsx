"use client";
import {useCallback,useEffect,useState} from "react";
import {useRouter} from "next/navigation";
import Link from "next/link";
import AdminV2Diagnostics from "./admin-v2-diagnostics";
import AdminV2Play from "./admin-v2-play";
import AdminCompatibleExport from "./admin-compatible-export";
const requestOptions=body=>({method:"POST",cache:"no-store",credentials:"same-origin",
 headers:{"Content-Type":"application/json","X-SPDecode-Admin-Action":"1"},body:JSON.stringify(body)});
const serviceList=[
 ["files","Archivos y textos","Solicitudes a motores de archivos y texto"],
 ["httpInjector","HTTP Injector Cloud","Importación de configuraciones EHI Cloud"],
 ["serverVpn","Server VPN","Descifrado de catálogos remotos de servidores VPN"],
];
const fmt=new Intl.NumberFormat("es-MX");
function Health({ok}){return <span className="sp-admin-health" data-ok={ok?"yes":"no"}><span aria-hidden="true"/> {ok?"Disponible":"No disponible"}</span>}
export default function AdminDashboard({mode="system"}){
 const [data,setData]=useState(null),[busy,setBusy]=useState(false);
 const [error,setError]=useState(""),[loading,setLoading]=useState(true);
 const [providerQuery,setProviderQuery]=useState(""),[providerFilter,setProviderFilter]=useState("all");
 const [clock,setClock]=useState(null);
 const [patchMonths,setPatchMonths]=useState(24);
 const [enforcePatch,setEnforcePatch]=useState(false);
 const [enforceBoot,setEnforceBoot]=useState(false);
 const [testHours,setTestHours]=useState(0);
 useEffect(()=>{
  const p=data?.v2DevicePolicy;
  if(!p)return;
  setPatchMonths(p.patchMonths);
  setEnforcePatch(p.enforcePatch);
  setEnforceBoot(p.enforceBoot);
 },[data?.v2DevicePolicy?.revision,data?.v2DevicePolicy?.expiresAt]);
 useEffect(()=>{setClock(Date.now());const t=setInterval(()=>setClock(Date.now()),60000);return()=>clearInterval(t);},[]);
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
 async function changeV1(field){
  if(!data?.v1Policy||busy)return;
  const enabled=!data.v1Policy[field];
  const protection=field==="advancedProtection";
  const warning=protection?(enabled?
   "¿Activar la protección avanzada V1? Las versiones antiguas de Android podrían perder acceso hasta actualizarse. V2 no cambia.":
   "¿Desactivar la protección avanzada V1? Se conservan la autenticación y los límites actuales de V1."):(enabled?
   "¿Habilitar API V1 con la política de protección seleccionada?":
   "¿Deshabilitar completamente API V1? Se rechazarán todas sus rutas, incluidas autenticación, salud, catálogos y descifrado. V2 y el panel seguirán disponibles.");
  if(!window.confirm(warning))return;
  setBusy(true);setError("");
  try{
   const confirmation=(protection?"V1_PROTECCION_":"API_V1_")+(enabled?"ACTIVAR":"DESACTIVAR");
   const res=await fetch(protection?"/api/admin/v1-protection":"/api/admin/v1-availability",
    requestOptions({enabled,confirmation,expectedRevision:data.v1Policy.revision}));
   if(!res.ok)throw Error(res.status===409?"La política cambió. Actualiza el estado e inténtalo de nuevo.":"El servidor rechazó el cambio ("+res.status+").");
   await refresh();
  }catch(e){setError(e.message||"No se pudo cambiar la política V1.");await refresh();}
  finally{setBusy(false);}
 }
 async function changeRetirement(){
  if(!data?.v1Policy||busy)return;
  const active=Boolean(data.v1Policy.retireAt),action=active?"cancel":"schedule";
  if(!window.confirm(active?
   "¿Cancelar la desactivación programada de API V1? No activará una API apagada manualmente.":
   "¿Programar el cierre de API V1 dentro de 48 horas? El servidor rechazará todas las peticiones V1, pero V2, el panel y la web permanecerán disponibles."))return;
  setBusy(true);setError("");
  try{
   const res=await fetch("/api/admin/v1-retirement",requestOptions({
    action,expectedRevision:data.v1Policy.revision,
    confirmation:active?"API_V1_CANCELAR_PROGRAMACION":"API_V1_PROGRAMAR_48H"}));
   const reply=await res.json();
   if(!res.ok||reply.status!=="ok")throw Error(res.status===409?
    "Conflicto de revisión; actualiza el estado e inténtalo de nuevo.":
    "No fue posible guardar la desactivación programada ("+res.status+").");
   await refresh();
  }catch(e){setError(e.message||"Error al cambiar la programación.");await refresh();}
  finally{setBusy(false);}
 }
 async function changeV2(){
  if(!data?.v2Policy||busy)return;
  const enabled=!data.v2Policy.enabled;
  const message=enabled?
   "¿Habilitar la API V2? Se seguirán exigiendo Play Integrity y las verificaciones criptográficas; la configuración privada del servidor debe estar completa.":
   "¿Deshabilitar API V2? Se rechazarán las nuevas peticiones V2, incluidas las de Android 1.1.24. V1 y el panel permanecerán disponibles.";
  if(!window.confirm(message))return;
  setBusy(true);setError("");
  try {
   const response=await fetch("/api/admin/v2-availability",
    requestOptions({enabled,confirmation:enabled?"API_V2_ACTIVAR":"API_V2_DESACTIVAR",
      expectedRevision:data.v2Policy.revision}));
   if(!response.ok)throw Error(response.status===409?
    "La política V2 cambió. Actualiza el estado e inténtalo de nuevo.":
    "El servidor rechazó el cambio V2 ("+response.status+").");
   await refresh();
  }catch(e){setError(e.message||"No se pudo actualizar V2.");await refresh();}
  finally{setBusy(false);}
 }
 async function changeV2Play(settings){
  if(!data?.v2PlayPolicy||busy)return;
  setBusy(true);setError("");
  try{
   const response=await fetch("/api/admin/v2-play-integrity",requestOptions({settings,
     confirmation:"V2_PLAY_CONFIGURAR",expectedRevision:data.v2PlayPolicy.revision}));
   if(!response.ok)throw Error(response.status===409?
     "La configuración cambió. Actualiza el estado e inténtalo de nuevo.":
     "No se guardó la configuración Play ("+response.status+").");
   await refresh();
  }catch(e){setError(e.message||"Error de política Play V2.");await refresh();}
  finally{setBusy(false);}
 }

 async function saveDevicePolicy(reset=false){
  if(!data?.v2DevicePolicy||busy)return;
  const months=reset?12:patchMonths,patch=reset?true:enforcePatch,boot=reset?true:enforceBoot;
  const duration=reset?0:testHours;
  if(!window.confirm("¿Guardar el perfil "+(duration?"durante "+duration+" horas":"sin caducidad")+
    "? Al exigir parches o bootloader bloqueado pueden perder acceso dispositivos compatibles con el perfil actual. Al vencer un perfil temporal se vuelve a observar ambas señales."))return;
  setBusy(true);setError("");
  try{
    const res=await fetch("/api/admin/v2-device-admission",requestOptions({
      patchMonths:months,enforcePatch:patch,enforceBoot:boot,
      durationHours:duration,expectedRevision:data.v2DevicePolicy.revision,
      confirmation:"V2_DISPOSITIVOS_CONFIGURAR"}));
    const answer=await res.json();
    if(!res.ok||answer.status!=="ok")throw Error(res.status===409?
      "La política ha cambiado. Vuelve a cargar el panel.":"No se guardó la política ("+res.status+").");
    await refresh();
  }catch(err){setError(err.message||"Error al guardar la política.");await refresh();}
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
   {mode==="overview"?<>
    <div className="admin-metric-grid">
     <article className="admin-card"><span className="muted">Correctos hoy · UTC</span><strong>{fmt.format(data.metrics.successfulDecodes)}</strong><small className="muted">Descifrados completados</small></article>
     <article className="admin-card"><span className="muted">Fallidos hoy · UTC</span><strong>{fmt.format(data.metrics.failedDecodes)}</strong><small className="muted">Errores técnicos nuevos</small></article>
     <article className="admin-card"><span className="muted">Servicios disponibles</span><strong>{[data.services.apiConfigured,data.services.redisConnected,data.services.workerReady].filter(Boolean).length}/3</strong><small className="muted">API, Redis y worker</small></article>
     <article className="admin-card"><span className="muted">Estado general</span><strong className="sp-admin-status-text">{data.maintenance?"Mantenimiento":"Operativo"}</strong><small className="muted">Según control global</small></article>
    </div>
   <div className="admin-grid">
     <section className="admin-card">
      <h2>Estado de la infraestructura</h2>
      {[["API configurada",data.services.apiConfigured],["Redis",data.services.redisConnected],["Worker",data.services.workerReady]].map(([name,ok])=><div className="admin-kv" key={name}><span>{name}</span><Health ok={ok}/></div>)}
      <p className="muted">Disponibilidad técnica al momento de actualizar. No representa una prueba de cada proveedor.</p>
     </section>
     <section className="admin-card">
      <h2>Accesos operativos</h2>
      <div className="sp-admin-quick-links">
       <Link href="/admin/analytics"><strong>Analítica</strong><span>Actividad, tendencias, filtros y exportación de estadísticas</span></Link>
       <Link href="/admin/reports"><strong>Incidencias</strong><span>Diagnósticos y reinicio de errores por formato</span></Link>
       <Link href="/admin/system"><strong>Servicios</strong><span>Disponibilidad de proveedores, mantenimiento y controles Cloud</span></Link>
      </div>
     </section>
    </div>
    <div className="admin-card sp-admin-overview-note">
     <strong>Estado de la distribución</strong>
     <p className="muted">Verificación de Google Play: {data.playAdmission?.integrityRequired?"obligatoria":"beta temporal (sin Play Integrity)"}. Proveedores configurados: {(data.providerControls?.providers||[]).filter(x=>x.configured).length} de {(data.providerControls?.providers||[]).length}. Catálogo Server VPN: versión {data.providerControls?.catalogVersion??"—"}.</p>
     <Link href="/admin/system">Administrar disponibilidad y servicios</Link>
    </div>
   </>:<>
    {mode==="infrastructure"&&<>
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
   </>}
   {mode==="exports"&&<AdminCompatibleExport/>}
   {mode==="api-v1"&&<section className="admin-card sp-admin-services">
    <h2>Administración de API V1</h2>
    <p className="muted">Desactivación programada independiente de V2. Se aplicará en cada solicitud a partir de la fecha del servidor, sin jobs ni procesos adicionales.</p>
    <div className="sp-admin-retirement">
     <h3>Retirar API V1 a las 48 horas</h3>
     <p className="muted">Al programar se guarda la fecha exacta en el volumen persistente. Una vez vencido el plazo, todas las rutas V1 se rechazarán. La API V2 y el panel conservarán su funcionamiento.</p>
     <p className="muted">Para volver a cambiar la disponibilidad manual de V1, cancela primero la fecha de retiro. El botón no publica ni actualiza Android.</p>
     {data.v1Policy?.retireAt?
       <><strong className="sp-admin-deadline">Fecha de cierre: {new Date(data.v1Policy.retireAt).toLocaleString("es-MX",{dateStyle:"full",timeStyle:"short"})}</strong>
       <p role="status" className="muted">{data.v1Policy.retired?"API V1 ya está retirada.":
        clock===null?"Consultando tiempo restante…":
        "Restante: "+Math.max(0,Math.floor((data.v1Policy.retireAt-clock)/3600000))+" h "+Math.max(0,Math.floor(((data.v1Policy.retireAt-clock)%3600000)/60000))+" min"}</p></>
       :<p className="muted">Todavía no se ha programado una fecha de cierre.</p>}
     <button className="button subtle" type="button" onClick={changeRetirement}
      disabled={busy||!data.v1Policy||(!data.v1Policy.retireAt&&!data.v1Policy.apiEnabled)}>
      {data.v1Policy?.retireAt?"Cancelar fecha de cierre":"Programar cierre en 48 horas"}</button>
    </div>
    {[['apiEnabled','API V1 habilitada',data.v1Policy?.apiEnabled?
      'V1 disponible con la política de protección seleccionada.':'Todas las rutas V1 están deshabilitadas.'],
      ['advancedProtection','Protección avanzada V1',data.v1Policy?.advancedProtection?
      'Las operaciones autenticadas de V1 exigen sesión vinculada y prueba V2.':'Se conserva la autenticación y seguridad habitual de V1.']].map(([field,title,note])=>(
      <div className="sp-admin-switch-row" key={field}>
       <div><strong>{title}</strong><small className="muted">{note}</small>
        {field==='advancedProtection'&&<small className="sp-admin-status-note">Activarlo puede impedir el acceso de versiones antiguas hasta actualizarse.</small>}
       </div>
       <button className="sp-admin-switch" role="switch" type="button" aria-label={title}
        aria-checked={Boolean(data.v1Policy?.[field])} disabled={busy||!data.v1Policy||(field==="apiEnabled"&&Boolean(data.v1Policy.retireAt))} onClick={()=>changeV1(field)}><span/></button>
      </div>
    ))}
   </section>}
   {mode==="api-v2"&&<section className="admin-card sp-admin-services">
    <h2>API V2 y verificación</h2>
    <p className="muted">Administración independiente de disponibilidad y Play Integrity de V2.</p>
     <div className="sp-admin-switch-row">
      <div><strong>API V2 habilitada</strong>
       <small className="muted">{data.v2Policy?.enabled?
        "V2 permite solicitudes autenticadas con todas sus verificaciones obligatorias.":
        "Las rutas V2 están deshabilitadas y rechazan nuevas peticiones."}</small>
       <small className="sp-admin-status-note">{data.v2Policy?.configured?
        "Requisitos V2 configurados en el servidor.":
        "Los requisitos de V2 no están completos; se requieren los servicios de autenticación indicados por la política actual."}</small>
      </div>
      <button type="button" className="sp-admin-switch" role="switch"
       aria-label="API V2 habilitada" aria-checked={Boolean(data.v2Policy?.enabled)}
       disabled={busy||!data.v2Policy} onClick={changeV2}><span/></button>
     </div>
     <AdminV2Play policy={data.v2PlayPolicy} runtime={data.v2Runtime} busy={busy} onSave={changeV2Play}/>
     <AdminV2Diagnostics hardware={data.attestationDiagnostics} play={data.admissionDiagnostics}/>
   <div className="sp-admin-device-policy">
     <h3>Compatibilidad y seguridad de dispositivos V2</h3>
     <p className="muted">Las señales de parche y arranque se observan por defecto. Puedes exigirlas por separado y guardar un perfil permanente o temporal.</p>
     <label htmlFor="v2-patch-years">Antigüedad máxima del parche</label>
     <select id="v2-patch-years" value={patchMonths} disabled={busy} onChange={e=>setPatchMonths(Number(e.target.value))}>
      <option value={12}>1 año (12 meses) · estricto</option>
      <option value={18}>1 año y medio</option>
      <option value={24}>2 años</option>
      <option value={36}>3 años</option>
      <option value={48}>4 años</option>
     </select>
     <div className="sp-admin-switch-row">
      <div><strong>Exigir parches Android, vendor y boot recientes</strong>
       <small className="muted">Si se desactiva, los parches antiguos se registran como observaciones y no bloquean el acceso.</small></div>
      <button className="sp-admin-switch" type="button" role="switch" aria-label="Comprobar parches V2"
       aria-checked={enforcePatch} disabled={busy} onClick={()=>setEnforcePatch(v=>!v)}><span/></button>
     </div>
     <div className="sp-admin-switch-row">
      <div><strong>Exigir Verified Boot y bootloader bloqueado</strong>
       <small className="muted">No indica de forma inequívoca si hay root; conserva la validación de certificados y la identidad APK.</small></div>
      <button className="sp-admin-switch" type="button" role="switch" aria-label="Comprobar arranque V2"
       aria-checked={enforceBoot} disabled={busy} onClick={()=>setEnforceBoot(v=>!v)}><span/></button>
     </div>
     <label htmlFor="v2-device-duration">Duración del perfil</label>
     <select id="v2-device-duration" value={testHours} disabled={busy} onChange={e=>setTestHours(Number(e.target.value))}>
      <option value={0}>Permanente (sin caducidad)</option><option value={1}>1 hora</option><option value={6}>6 horas</option>
      <option value={24}>24 horas</option><option value={48}>48 horas</option>
     </select>
     <p className="sp-admin-device-status" role="status">
      {data.v2DevicePolicy?.expired?"Perfil temporal vencido: parches y arranque en observación.":
       data.v2DevicePolicy?.permanent?"Perfil guardado sin caducidad.":
       "Perfil activo hasta "+new Date(data.v2DevicePolicy?.expiresAt).toLocaleString("es-MX")}
     </p>
     <p className="muted">Aunque desactives ambos controles, siguen obligatorios Google Key Attestation, el certificado de confianza, la identidad y firma de SP-DECODE, las pruebas de sesión y el cifrado HPKE.</p>
     <div className="sp-admin-device-actions">
      <button className="button primary" type="button" disabled={busy||!data.v2DevicePolicy}
       onClick={()=>saveDevicePolicy(false)}>Guardar perfil de dispositivos</button>
      <button className="button subtle" type="button" disabled={busy||!data.v2DevicePolicy}
       onClick={()=>saveDevicePolicy(true)}>Restaurar perfil estricto</button>
     </div>
   </div>
   </section>}

   {mode==="play"&&<>
   <section className="admin-card sp-admin-services">
    <div className="sp-admin-section-heading"><div><h2>Google Play Integrity de API V1</h2>
     <p className="muted">Esta política afecta a API V1. Los controles permanentes de Play para V2 están en la sección API V2.</p></div></div>
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
   </section>   </>}

   {mode==="providers"&&<>
   <section className="admin-card sp-admin-services">
    <div className="sp-admin-section-heading"><div>
     <h2>Disponibilidad de importaciones remotas</h2>
     <p className="muted">Activa o desactiva HTTP Injector Cloud, el catálogo Servidores VPN y cada proveedor individual. Estos controles no requieren QA. El servidor debe tener habilitados previamente los requisitos privados de cada integración.</p>
    </div><span className="sp-admin-chip">Servicios Cloud</span></div>
    <div className="admin-kv"><span>Versión del catálogo Server VPN</span><strong>{data.providerControls?.catalogVersion??"—"}</strong></div>
    <div className="sp-admin-provider-tools">
     <label>Buscar proveedor<input type="search" value={providerQuery} onChange={event=>setProviderQuery(event.target.value)}
      placeholder="Nombre o identificador" maxLength={80}/></label>
     <label>Estado<select value={providerFilter} onChange={event=>setProviderFilter(event.target.value)}>
      <option value="all">Todos</option>
      <option value="enabled">Habilitados</option>
      <option value="disabled">Deshabilitados</option>
      <option value="unconfigured">No configurados</option>
     </select></label>
    </div>
    <p className="muted">Mostrando {(data.providerControls?.providers||[]).filter(p=>
      (p.name.toLowerCase().includes(providerQuery.trim().toLowerCase())||p.id.toLowerCase().includes(providerQuery.trim().toLowerCase()))&&
      (providerFilter==="all"||providerFilter==="enabled"&&p.enabled||providerFilter==="disabled"&&p.configured&&!p.enabled||providerFilter==="unconfigured"&&!p.configured)
     ).length} de {(data.providerControls?.providers||[]).length} proveedores.</p>
    {(data.providerControls?.providers||[]).filter(p=>
      (p.name.toLowerCase().includes(providerQuery.trim().toLowerCase())||p.id.toLowerCase().includes(providerQuery.trim().toLowerCase()))&&
      (providerFilter==="all"||providerFilter==="enabled"&&p.enabled||providerFilter==="disabled"&&p.configured&&!p.enabled||providerFilter==="unconfigured"&&!p.configured)
     ).map(provider=>{
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
   </section>   </>}

   {mode==="maintenance"&&<>
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
   </section>   </>}

   </>}
  </>}
  <div className="admin-actions">
   <button className="button subtle" onClick={()=>refresh()} disabled={busy} type="button">Actualizar estado</button>
   <button className="button subtle" onClick={logout} disabled={busy} type="button">Cerrar sesión</button>
  </div>
 </section>;
}
