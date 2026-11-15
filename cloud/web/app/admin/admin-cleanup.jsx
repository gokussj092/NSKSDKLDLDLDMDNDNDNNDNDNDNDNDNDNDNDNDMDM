"use client";
import {useCallback,useEffect,useState} from 'react';
import {useRouter} from 'next/navigation';
export default function CleanupDashboard(){
 const router=useRouter(),[data,setData]=useState(null),[error,setError]=useState(''),[message,setMessage]=useState(''),[busy,setBusy]=useState(false);
 const [enabled,setEnabled]=useState(false),[hours,setHours]=useState(168);
 const refresh=useCallback(async()=>{
  const r=await fetch('/api/admin/cleanup',{credentials:'same-origin',cache:'no-store'});
  if(r.status===401){router.replace('/admin/login');return;}
  if(!r.ok)throw Error('No se pudo consultar la política de limpieza.');
  const v=await r.json();setData(v);setEnabled(v.policy.enabled);setHours(v.policy.retentionHours);setError('');
 },[router]);
 useEffect(()=>{refresh().catch(e=>setError(e.message));},[refresh]);
 async function update(body){
  if(busy)return;setBusy(true);setError('');setMessage('');
  try{const r=await fetch('/api/admin/cleanup',{method:'POST',credentials:'same-origin',cache:'no-store',headers:{'Content-Type':'application/json','X-SPDecode-Admin-Action':'1'},body:JSON.stringify(body)});
   if(!r.ok)throw Error('La solicitud fue rechazada. Comprueba tu sesión y la base de datos.');
   await refresh();setMessage(body.action==='request'?'Limpieza solicitada. Se ejecutará mediante el temporizador del VPS si está instalado.':'Política de mantenimiento guardada.');
  }catch(e){setError(e.message);}finally{setBusy(false);}
 }
 return <div className="sp-cleanup-dashboard">
  <section className="sp-admin-commerce-hero"><div><span className="sp-admin-commercial-kicker">SP-DECODE · OPERACIÓN</span><h2>Mantenimiento y caché</h2><p>Controla la limpieza de recursos regenerables, sin borrar claves, compras, licencias ni trabajos en proceso.</p></div><img src="/icon.svg" alt="SP-DECODE" width="58" height="58"/></section>
  {error&&<p role="alert" className="form-message error">{error}</p>}{message&&<p role="status" className="form-message">{message}</p>}
  {!data?<div className="admin-card" role="status">Consultando configuración...</div>:<>
   <div className="sp-admin-cleanup-stats">
    <article><span>Proceso de limpieza</span><strong>{data.policy.enabled?'Programado':'Desactivado'}</strong><small>{data.policy.requested?'Solicitud manual pendiente':'Sin solicitud pendiente'}</small></article>
    <article><span>Retención mínima</span><strong>{data.policy.retentionHours} horas</strong><small>Caché de compilación antigua</small></article>
    <article><span>Última ejecución</span><strong>{data.policy.lastRunAt?new Date(data.policy.lastRunAt).toLocaleDateString('es-MX'):'Sin registros'}</strong><small>{data.policy.lastResult||'No ejecutado'}</small></article>
   </div>
   <section className="admin-card sp-admin-cleanup-panel"><div className="sp-admin-cleanup-panel-head"><div><span className="sp-admin-commercial-kicker">ALCANCE CONTROLADO</span><h2>¿Qué se puede limpiar?</h2></div><span className="sp-cleanup-safe">Protección activa</span></div>
    <div className="sp-admin-cleanup-items">
     <article><span className="sp-admin-cleanup-art">✦</span><div><strong>Caché de compilación Docker sin uso</strong><small>Solo entradas anteriores al periodo configurado. Docker no elimina caché usada por compilaciones activas.</small></div></article>
     <article><span className="sp-admin-cleanup-art">✓</span><div><strong>Temporales de análisis APK</strong><small>El servicio APK QA ya tiene su propio recolector. No se ejecuta ninguna eliminación paralela desde esta sección.</small></div></article>
     <article><span className="sp-admin-cleanup-art">◎</span><div><strong>Datos protegidos</strong><small>PostgreSQL, Redis, claves, firmas, archivos de respaldo, APK entregables, catálogos y trabajos activos nunca se incluyen.</small></div></article>
    </div>
   </section>
   <section className="admin-card sp-admin-cleanup-panel"><h2>Programación</h2><p className="muted">La tarea del VPS revisa cada 15 minutos si existe una solicitud. La limpieza automática se realiza como máximo una vez cada 24 horas. Para habilitar la ejecución es necesario instalar primero el temporizador con <code>spdecode cleanup install-timer</code>.</p>
    <div className="sp-admin-cleanup-controls"><label className="sp-admin-cleanup-switch"><input type="checkbox" checked={enabled} onChange={e=>setEnabled(e.target.checked)}/><span>Habilitar limpieza automática</span></label>
    <label>Conservar caché por al menos<select value={hours} onChange={e=>setHours(Number(e.target.value))}><option value={168}>7 días (168 h)</option><option value={336}>14 días (336 h)</option><option value={720}>30 días (720 h)</option></select></label></div>
    <div className="sp-admin-cleanup-actions"><button type="button" className="button" disabled={busy} onClick={()=>{if(window.confirm('¿Guardar la programación de limpieza de caché Docker?'))update({action:'configure',enabled,retentionHours:hours});}}>Guardar programación</button><button type="button" className="button sp-cleanup-secondary" disabled={busy||data.policy.requested} onClick={()=>{if(window.confirm('¿Solicitar una limpieza de caché Docker antigua? No se borrarán volúmenes, bases de datos ni archivos de usuario. La acción afectará la caché de compilación sin uso del host Docker dedicado.'))update({action:'request'});}}>Solicitar limpieza ahora</button></div>
    <small className="muted">El proceso se negará a limpiar cuando detecte otros contenedores activos ajenos a SP-DECODE. Las cifras de ahorro solo se conocerán después de ejecutar Docker BuildKit.</small>
   </section>
  </>}
 </div>;
}
