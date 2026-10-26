"use client";
import {useEffect,useState} from "react";
import {useRouter} from "next/navigation";
const labels={files:"Archivos / texto",httpInjector:"HTTP Injector Cloud",serverVpn:"Server VPN"};
const fmt=new Intl.NumberFormat("es-MX");
export default function AdminDiagnostics({showIncidents=true}){
 const [days,setDays]=useState(7),[data,setData]=useState(null),[error,setError]=useState("");
 const [loading,setLoading]=useState(true);
 const router=useRouter();
 useEffect(()=>{
  const controller=new AbortController();
  const load=async()=>{
   if(controller.signal.aborted)return;
   setLoading(true);
   try{
    const response=await fetch("/api/admin/incidents?days="+days,
      {credentials:"same-origin",cache:"no-store",signal:controller.signal});
    if(response.status===401){router.replace("/admin/login");return;}
    if(!response.ok)throw Error("No se pudo consultar el diagnóstico.");
    const payload=await response.json();
    if(payload.status!=="ok")throw Error("Datos de diagnóstico no válidos.");
    if(!controller.signal.aborted){setData(payload);setError("");}
   }catch(e){if(e.name!=="AbortError"&&!controller.signal.aborted)setError(e.message);}
   finally{if(!controller.signal.aborted)setLoading(false);}
  };
  load();
  window.addEventListener("spdecode:admin-telemetry-changed",load);
  return()=>{controller.abort();window.removeEventListener("spdecode:admin-telemetry-changed",load);};
 },[days,router]);
 return <section className="sp-admin-diagnostics">
  <div className="admin-report-toolbar">
   <h2>Diagnóstico e instalaciones</h2>
   <div className="admin-range" role="group" aria-label="Periodo de incidencias">
    <button type="button" aria-pressed={days===1} onClick={()=>setDays(1)}>Hoy</button>
    <button type="button" aria-pressed={days===7} onClick={()=>setDays(7)}>7 días</button>
   </div>
  </div>
  {loading&&<p role="status" className="muted">Consultando eventos técnicos…</p>}
  {error&&<p className="form-message error" role="alert">{error}</p>}
  {data&&<>
   <div className="admin-metric-grid">
    <article className="admin-card"><span className="muted">Instalaciones activas hoy</span>
     <strong>{fmt.format(data.installations.activeToday)}</strong><small className="muted">Estimación de instalaciones Cloud</small></article>
    <article className="admin-card"><span className="muted">Instalaciones activas · 30 días</span>
     <strong>{fmt.format(data.installations.activeLast30Days)}</strong><small className="muted">Estimación, no personas únicas</small></article>
    <article className="admin-card"><span className="muted">Errores actuales</span>
     <strong>{fmt.format(data.incidents.filter(x=>x.severity!=="warning").length)}</strong><small className="muted">Desde el reinicio correspondiente · muestra limitada</small></article>
    <article className="admin-card"><span className="muted">Advertencias de compatibilidad</span>
     <strong>{fmt.format(data.incidents.filter(x=>x.severity==="warning").length)}</strong><small className="muted">No son fallos operativos</small></article>
    <article className="admin-card"><span className="muted">Reportes manuales</span>
     <strong>{fmt.format(data.incidents.filter(x=>x.source==="user").length)}</strong><small className="muted">Enviados expresamente</small></article>
   </div>
   <p className="muted">Las instalaciones son estimaciones de dispositivos que aceptaron las condiciones Cloud y estuvieron activos. No representan personas únicas. No se almacenan identificadores en claro y los incidentes no incluyen archivos.</p>
   {showIncidents&&<section className="admin-card admin-report-card">
    <h2>Incidentes recientes</h2>
    <div className="admin-table-wrap"><table className="admin-table"><thead><tr>
     <th>UTC</th><th>Estado</th><th>Origen</th><th>Servicio</th><th>Formato</th><th>Código</th><th>Tamaño</th><th>Referencia</th>
    </tr></thead><tbody>
     {data.incidents.map(row=><tr key={row.id}>
      <td>{new Date(row.at).toLocaleString("es-MX",{timeZone:"UTC"})}</td>
      <td>{row.severity==="warning"?"Advertencia":"Error"}</td><td>{row.source==="user"?"Usuario":"Servidor"}</td>
      <td>{labels[row.service]||"Otro"}</td><td>{row.format}</td>
      <td><code>{row.code}</code></td><td>{row.sizeBucket}</td>
      <td title={row.id}><code>{row.id.slice(0,8)}</code></td>
     </tr>)}
     {!data.incidents.length&&<tr><td colSpan={8}>Sin incidencias registradas en este periodo.</td></tr>}
    </tbody></table></div>
    <p className="muted">Retención: {data.retentionDays} días, máximo 150 registros por día. Las solicitudes de contraseña/HWID y las cancelaciones no crean incidencias automáticas. Las versiones incompatibles se clasifican como advertencias. El reinicio de errores se gestiona en Informes.</p>
   </section>}
  </>}
 </section>;
}
