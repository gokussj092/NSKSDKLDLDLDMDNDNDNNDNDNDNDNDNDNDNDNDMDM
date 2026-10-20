"use client";
import {useCallback,useEffect,useState} from "react";
import {useRouter} from "next/navigation";
const number=new Intl.NumberFormat("es-MX");
const size=n=>n<1024?number.format(n)+" B":n<1024**2?(n/1024).toFixed(1)+" KiB":(n/1024**2).toFixed(2)+" MiB";
const ErrorNames={
 AUTH_FAILED:"Autenticación del archivo",INVALID_CREDENTIALS:"Credenciales incorrectas",
 PASSWORD_REQUIRED:"Se requiere contraseña",HWID_REQUIRED:"Se requiere HWID",
 HWID_PASSWORD_REQUIRED:"Contraseña y HWID necesarios",DECODE_FAILED:"No se pudo descifrar",
 ENGINE_TIMEOUT:"Tiempo de espera agotado",ENGINE_UNAVAILABLE:"Motor no disponible",
 UNSUPPORTED_FORMAT:"Formato sin soporte",REMOTE_PROVIDER_UNAVAILABLE:"Proveedor VPN sin respuesta",
 REMOTE_DECODER_FAILED:"Descifrado remoto fallido",REMOTE_RESPONSE_INVALID:"Respuesta remota inválida",
 REMOTE_INTEGRITY_FAILED:"Error de integridad del proveedor",
 INPUT_TOO_LARGE:"Archivo demasiado grande",OUTPUT_TOO_LARGE:"Resultado excesivo",
 SERVICE_UNAVAILABLE:"Servicio no disponible",SERVICE_MAINTENANCE:"Servicio en mantenimiento",
 OTHER_ERROR:"Otro error controlado"
};
const channels=[
 ["files","Archivos y textos"],
 ["httpInjector","HTTP Injector Cloud"],
 ["serverVpn","Server VPN"]
];
function Rate({success,failed}){
 const total=success+failed;
 return <span>{total?Math.round(success/total*100)+" %":"—"}</span>;
}
function DailyLine({days}){
 const max=Math.max(1,...days.map(d=>d.successfulDecodes),...days.map(d=>d.failedDecodes));
 const points=key=>days.map((d,i)=>{
  const x=18+(days.length===1?0:i*664/(days.length-1));
  const y=165-d[key]/max*138;
  return [x,y];
 });
 const path=key=>points(key).map(([x,y],i)=>(i===0?"M ":"L ")+x.toFixed(1)+" "+y.toFixed(1)).join(" ");
 const sums=days.reduce((total,d)=>total+d.successfulDecodes+d.failedDecodes,0);
 return <section className="admin-card admin-report-card">
  <div className="sp-admin-section-heading"><div><h2>Actividad de descifrado</h2><p className="muted">Serie por día · UTC</p></div>
   <div className="sp-admin-legend"><span><i className="sp-admin-key-success"/> Correctos</span><span><i className="sp-admin-key-error"/> Fallidos</span></div>
  </div>
  {sums===0?<p className="muted">Todavía no hay descifrados registrados durante este intervalo.</p>:
   <div className="sp-admin-line-chart">
    <svg viewBox="0 0 700 190" role="img" aria-label="Serie temporal de descifrados correctos y fallidos" preserveAspectRatio="none">
     {[35,80,125,165].map(y=><line key={y} x1="18" y1={y} x2="682" y2={y} stroke="#313131" strokeWidth="1"/>)}
     <path d={path("successfulDecodes")} stroke="#f7f7f7" strokeWidth="3" fill="none" strokeLinejoin="round" strokeLinecap="round"/>
     <path d={path("failedDecodes")} stroke="#888888" strokeWidth="2.5" fill="none" strokeLinejoin="round" strokeLinecap="round"/>
     {days.length===1&&points("successfulDecodes").map(([x,y],i)=><circle key={i} cx={x} cy={y} r="5" fill="#f7f7f7"/>)}
    </svg>
    <div className="sp-admin-chart-labels">{days.map(d=><small key={d.date}>{d.date.slice(5)}</small>)}</div>
   </div>}
 </section>;
}
function HourlyBars({hours}){
 const max=Math.max(1,...hours.map(h=>h.successfulDecodes+h.failedDecodes));
 const total=hours.reduce((n,h)=>n+h.successfulDecodes+h.failedDecodes,0);
 return <section className="admin-card admin-report-card">
  <div className="sp-admin-section-heading"><div><h2>Actividad de las últimas 48 horas</h2><p className="muted">Intervalos horarios · UTC · equivalente al gráfico de tiempo real de YouTube Studio</p></div></div>
  {total===0?<p className="muted">La gráfica aparecerá cuando se registren nuevas operaciones con el contador horario.</p>:
   <div className="sp-admin-hourly-scroll"><div className="sp-admin-hourly" role="img" aria-label="Número de solicitudes procesadas por hora durante las últimas 48 horas">
    {hours.map((h,i)=><div className="sp-admin-hour" key={h.hour} title={h.hour+": "+(h.successfulDecodes+h.failedDecodes)+" operaciones"}
     style={{height:Math.max(1,(h.successfulDecodes+h.failedDecodes)/max*100)+"%"}}>
     {(i%8===0)&&<span>{h.hour.slice(11,13)}h</span>}
    </div>)}
   </div></div>}
  <small className="muted">Retención limitada. Las cifras anteriores al despliegue de esta telemetría no se reconstruyen.</small>
 </section>;
}
function FormatTable({rows,empty}){
 return <div className="admin-table-wrap"><table className="admin-table">
  <thead><tr><th>Formato / proveedor</th><th>Intentos</th><th>Correctos</th><th>Fallidos</th><th>Éxito</th></tr></thead>
  <tbody>{rows.map(row=><tr key={row.extension}>
   <th scope="row">{row.extension.startsWith("vpn-")?row.extension.slice(4):row.extension==="nur-catalog"?"NUR Tunnel":row.extension==="other"?"No reconocido":row.extension==="text"?"Texto":row.extension==="ehi"?"HTTP Injector Cloud":"."+row.extension}</th>
   <td>{number.format(row.attempts)}</td><td>{number.format(row.successfulDecodes)}</td>
   <td>{number.format(row.failedDecodes)}</td><td><Rate success={row.successfulDecodes} failed={row.failedDecodes}/></td>
  </tr>)}
  {!rows.length&&<tr><td colSpan={5}>{empty||"Sin operaciones registradas"}</td></tr>}
  </tbody></table></div>;
}
function CategoryTable({name,rows}){
 return <section className="admin-card admin-report-card"><div className="sp-admin-section-heading"><div><h2>{name}</h2><p className="muted">Motor o proveedor · resultados procesados</p></div></div>
  <FormatTable rows={rows}/>
 </section>;
}
function Incidents({report}){
 const all=report.extensions||[];
 const vpn=all.filter(x=>x.extension.startsWith("vpn-")||x.extension==="nur-catalog");
 const ehi=all.filter(x=>x.extension==="ehi");
 const files=all.filter(x=>!vpn.includes(x)&&!ehi.includes(x));
 const errorSections=(report.serviceErrors||[]).length?[
   ["Archivos y textos","files"],["HTTP Injector Cloud","httpInjector"],["Server VPN","serverVpn"]
 ]:[];
 return <>
  <CategoryTable name="Archivos y textos" rows={files}/>
  <CategoryTable name="HTTP Injector Cloud" rows={ehi}/>
  <CategoryTable name="Servidores VPN" rows={vpn}/>
  {errorSections.map(([name,id])=><section className="admin-card admin-report-card" key={id}>
   <h2>Errores · {name}</h2>
   <div className="admin-table-wrap"><table className="admin-table"><thead><tr><th>Motivo</th><th>Código seguro</th><th>Incidentes</th></tr></thead>
   <tbody>{(report.serviceErrors||[]).filter(x=>x.service===id).map(e=><tr key={e.code}>
    <td>{ErrorNames[e.code]||e.code.replaceAll("_"," ")}</td><td><code>{e.code}</code></td><td>{number.format(e.count)}</td>
   </tr>)}
   {!(report.serviceErrors||[]).some(x=>x.service===id)&&<tr><td colSpan={3}>No se registraron errores de este servicio.</td></tr>}
   </tbody></table></div>
  </section>)}
  <section className="admin-card admin-report-card"><h2>Incidencias por extensión y código</h2>
   <div className="admin-table-wrap"><table className="admin-table"><thead><tr><th>Formato</th><th>Error</th><th>Casos</th></tr></thead>
   <tbody>{(report.incidents||[]).map((e,i)=><tr key={e.extension+":"+e.code+":"+i}><td>{e.extension}</td><td>{ErrorNames[e.code]||e.code}</td><td>{number.format(e.count)}</td></tr>)}
   {!report.incidents?.length&&<tr><td colSpan={3}>No hay errores registrados.</td></tr>}</tbody></table></div>
  </section>
 </>;
}
export default function AdminReport({view="analytics"}){
 const [days,setDays]=useState(7),[report,setReport]=useState(null);
 const [loading,setLoading]=useState(true),[error,setError]=useState("");
 const router=useRouter();
 const refresh=useCallback(async signal=>{
  setLoading(true);
  try{
   const response=await fetch("/api/admin/reports?days="+days,{cache:"no-store",credentials:"same-origin",signal});
   if(response.status===401){router.replace("/admin/login");return;}
   if(!response.ok)throw Error("No se pudo consultar el informe ("+response.status+").");
   const json=await response.json();
   if(json.status!=="ok"||!json.report)throw Error("Respuesta inválida del servidor.");
   setReport(json.report);setError("");
  }catch(err){if(err.name!=="AbortError")setError(err.message||"No se pudo cargar.");}
  finally{if(!signal?.aborted)setLoading(false);}
 },[days,router]);
 useEffect(()=>{const ac=new AbortController();refresh(ac.signal);return()=>ac.abort();},[refresh]);
 const services=report?.serviceBreakdown||[];
 return <section className="sp-admin-report">
  <div className="admin-report-toolbar">
   <div className="admin-range" role="group" aria-label="Periodo estadístico">
    <button type="button" aria-pressed={days===1} onClick={()=>setDays(1)}>Hoy · UTC</button>
    <button type="button" aria-pressed={days===7} onClick={()=>setDays(7)}>Últimos 7 días</button>
   </div>
   <button type="button" className="button subtle" onClick={()=>refresh()} disabled={loading}>Actualizar datos</button>
  </div>
  {error&&<div className="form-message error" role="alert">{error}</div>}
  {loading&&<p className="muted" role="status">Consultando estadísticas…</p>}
  {report&&<>
   {view!=="overview"&&<div className="admin-metric-grid">
    <article className="admin-card"><span className="muted">Procesamientos</span><strong>{number.format(report.totalDecodes)}</strong></article>
    <article className="admin-card"><span className="muted">Correctos</span><strong>{number.format(report.successfulDecodes)}</strong></article>
    <article className="admin-card"><span className="muted">Fallidos</span><strong>{number.format(report.failedDecodes)}</strong></article>
    <article className="admin-card"><span className="muted">Entrada procesada</span><strong>{size(report.inputBytes)}</strong></article>
   </div>}
   <p className="muted">Retención de {report.retentionDays} días. Los contadores no incluyen el contenido de archivos, credenciales, IP ni identificadores personales. Las métricas históricas anteriores al registro por servicio no se reclasifican.</p>
   {view!=="reports"?<>
    <DailyLine days={report.daily||[]}/>
    <HourlyBars hours={report.hourlyLast48||[]}/>
    <section className="admin-card admin-report-card"><h2>Operaciones por servicio</h2>
     <div className="admin-table-wrap"><table className="admin-table"><thead><tr><th>Servicio</th><th>Correctos</th><th>Fallidos</th><th>Éxito</th></tr></thead>
      <tbody>{channels.map(([id,name])=>{const item=services.find(x=>x.service===id)||{successfulDecodes:0,failedDecodes:0};return <tr key={id}>
       <th scope="row">{name}</th><td>{number.format(item.successfulDecodes)}</td><td>{number.format(item.failedDecodes)}</td>
       <td><Rate success={item.successfulDecodes} failed={item.failedDecodes}/></td>
      </tr>;})}</tbody>
     </table></div>
    </section>
    {view==="analytics"&&<CategoryTable name="Desglose por extensión y proveedor" rows={report.extensions||[]}/>}
   </>:<Incidents report={report}/>}
  </>}
 </section>;
}
