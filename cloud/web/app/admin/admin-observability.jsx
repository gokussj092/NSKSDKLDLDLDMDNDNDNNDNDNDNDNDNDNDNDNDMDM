"use client";
import {useCallback,useEffect,useState} from "react";
import {useRouter} from "next/navigation";
const fmt=new Intl.NumberFormat("es-MX");
const percent=n=>n===null||n===undefined?"Sin datos":n.toFixed(1)+" %";
const ms=n=>n===null||n===undefined?"Sin muestras":fmt.format(n)+" ms";
const time=s=>s?new Date(s).toLocaleString("es-MX",{timeZone:"UTC"})+" UTC":"—";
const reason={network:"Red/proveedor",timeout:"Tiempo agotado",
 engine:"Motor",response:"Respuesta incorrecta",compatibility:"Incompatibilidad",
 other:"Otro"};
function Panel({title,subtitle,children}){
 return <section className="admin-card admin-report-card">
  <div className="sp-admin-section-heading"><div><h2>{title}</h2><p className="muted">{subtitle}</p></div></div>
  {children}
 </section>;
}
export default function AdminObservability({mode="analytics"}){
 const [days,setDays]=useState(7),[data,setData]=useState(null),
  [error,setError]=useState(""),[loading,setLoading]=useState(true);
 const router=useRouter();
 const refresh=useCallback(async(signal,quiet=false)=>{
  if(!quiet)setLoading(true);
  try{
   const response=await fetch("/api/admin/observability?days="+days,
    {credentials:"same-origin",cache:"no-store",signal});
   if(response.status===401){router.replace("/admin/login");return;}
   if(!response.ok)throw Error("No se pudo consultar el estado operativo.");
   const json=await response.json();
   if(json.status!=="ok")throw Error("Respuesta de observabilidad inválida.");
   if(!signal?.aborted){setData(json);setError("");}
  }catch(err){if(err.name!=="AbortError")setError(err.message||"Error de observabilidad");}
  finally{if(!signal?.aborted)setLoading(false);}
 },[days,router]);
 useEffect(()=>{
  const controller=new AbortController();
  refresh(controller.signal);
  const timer=setInterval(()=>{if(!controller.signal.aborted)refresh(controller.signal,true);},60000);
  return()=>{controller.abort();clearInterval(timer);};
 },[refresh]);
 const ops=data?.observability||{},health=data?.health||{};
 const comparison=data?.report?.comparisons||[];
 const perf=ops.performance||[],alerts=ops.alerts||[];
 return <section className="sp-admin-observability" aria-label="Observabilidad operativa">
  <div className="admin-report-toolbar">
   <h2>Observabilidad operativa</h2>
   <div className="sp-admin-toolbar-actions">
    <div className="admin-range" role="group" aria-label="Periodo de observabilidad">
     <button type="button" aria-pressed={days===1} onClick={()=>setDays(1)}>Hoy</button>
     <button type="button" aria-pressed={days===7} onClick={()=>setDays(7)}>7 días</button>
    </div>
    <button type="button" className="button subtle" onClick={()=>refresh()} disabled={loading}>Actualizar</button>
   </div>
  </div>
  {error&&<p role="alert" className="form-message error">{error}</p>}
  {loading&&<p className="muted" role="status">Consultando telemetría agregada…</p>}
  {data&&<>
   <div className="sp-admin-charts-grid">
    <Panel title="Alertas automáticas de proveedores" subtitle="Se actualiza cada minuto; sin correos ni datos de clientes">
     <p className="muted">Reglas: tres fallos consecutivos de red/timeout, o al menos cinco errores entre las últimas diez operaciones. Máximo una alerta por condición y hora.</p>
     {alerts.length?<div className="sp-admin-alert-list">
      {alerts.slice(0,12).map((a,i)=><div className="sp-admin-alert-row" key={a.at+":"+a.format+":"+i}>
       <strong>{a.format.replace(/^vpn-/,"")}</strong>
       <span>{a.type==="unresponsive"?"Posible proveedor sin respuesta":"Tasa elevada de fallos"}</span>
       <small className="muted">{time(a.at)} · {a.failures}/{a.recent} operaciones</small>
      </div>)}
     </div>:<p className="muted">No se han disparado alertas recientes.</p>}
    </Panel>
    <Panel title="Estado del servidor" subtitle="Medidas seguras y límites de visibilidad del contenedor Docker">
     <div className="admin-kv"><span>Worker</span><strong>{health.workerReady?"Disponible":"No disponible"}</strong></div>
     <div className="admin-kv"><span>Redis</span><strong>{health.redisReady?"Disponible":"No disponible"}</strong></div>
     <div className="admin-kv"><span>CPU web (contenedor)</span><strong>{percent(health.cpuPercent)}</strong></div>
     <div className="admin-kv"><span>RAM web (contenedor)</span><strong>{health.memoryUsedBytes===null?"No disponible":(health.memoryUsedBytes/1048576).toFixed(1)+" MiB"}{health.memoryLimitBytes?" / "+(health.memoryLimitBytes/1048576).toFixed(1)+" MiB":""}</strong></div>
     <div className="admin-kv"><span>Cola de trabajo</span><strong>Sin cola persistente</strong></div>
     <p className="muted">La CPU/RAM indicada corresponde al contenedor web, NO a toda la VPS. El uso de CPU puede aparecer tras la segunda lectura. No hay métricas de host ni cola persistente configuradas.</p>
    </Panel>
   </div>
   {mode!=="system"&&<>
    <Panel title="Antes y después de una corrección" subtitle="Líneas base de reinicios · tasas históricas y operaciones posteriores">
     <div className="admin-table-wrap"><table className="admin-table"><thead><tr>
      <th>Extensión / proveedor</th><th>Reinicio (UTC)</th><th>Antes</th><th>Errores nuevos</th><th>Después</th>
     </tr></thead><tbody>
      {comparison.map(x=><tr key={x.extension}><th>{x.extension}</th><td>{time(x.resetAt)}</td>
       <td>{x.beforeAttempts===null?"Sin histórico":fmt.format(x.beforeErrors)+"/"+fmt.format(x.beforeAttempts)+" · "+percent(x.beforeErrorPercent)}</td>
       <td>{fmt.format(x.afterErrors)} de {fmt.format(x.afterAttempts)}</td>
       <td>{percent(x.afterErrorPercent)}</td></tr>)}
      {!comparison.length&&<tr><td colSpan={5}>Reinicia los errores de un formato para iniciar una comparación.</td></tr>}
     </tbody></table></div>
     <p className="muted">La comparación utiliza un máximo de siete días UTC. Cuando faltan muestras anteriores o posteriores, no se calcula una tasa. Nunca se inventan datos históricos.</p>
    </Panel>
    <Panel title="Latencia por motor o proveedor" subtitle="Media y P95 estimado por histograma, sin almacenar solicitudes ni resultados">
     <div className="admin-table-wrap"><table className="admin-table"><thead><tr>
      <th>Motor / proveedor</th><th>Operaciones</th><th>Con tiempo</th><th>Media</th><th>P95 (límite superior)</th>
     </tr></thead><tbody>
      {perf.map(x=><tr key={x.scope+":"+x.label}>
       <th>{x.scope==="service"?"Servicio: ":"Formato: "}{x.label}</th>
       <td>{fmt.format(x.events)}</td><td>{fmt.format(x.count)}</td>
       <td>{ms(x.meanMs)}</td><td>{ms(x.p95UpperBoundMs)}</td></tr>)}
      {!perf.length&&<tr><td colSpan={5}>Todavía no hay operaciones posteriores al despliegue de esta instrumentación.</td></tr>}
     </tbody></table></div>
     <p className="muted">P95 es un límite superior calculado por rangos, no un percentil exacto. La duración incluye la comunicación con el worker; para proveedores remotos también la descarga.</p>
    </Panel>
    <Panel title="Diagnóstico de causas" subtitle="Errores de red, agotamiento de tiempo, motor, respuesta e incompatibilidad">
     <div className="admin-table-wrap"><table className="admin-table"><thead><tr>
      <th>Motor / proveedor</th>{Object.keys(reason).map(k=><th key={k}>{reason[k]}</th>)}
     </tr></thead><tbody>
      {perf.filter(x=>Object.values(x.categories).some(Boolean)).map(x=><tr key={x.scope+":"+x.label}>
       <th>{x.label}</th>{Object.keys(reason).map(k=><td key={k}>{fmt.format(x.categories[k]||0)}</td>)}
      </tr>)}
      {!perf.some(x=>Object.values(x.categories).some(Boolean))&&<tr><td colSpan={7}>Sin causas técnicas recientes.</td></tr>}
     </tbody></table></div>
    </Panel>
    <div className="sp-admin-charts-grid">
     <Panel title="Versiones de SP-DECODE" subtitle="Agrupadas exclusivamente cuando la aplicación envía una versión válida">
      {(ops.versions||[]).map(x=><div className="admin-kv" key={x.version}><span>{x.version==="not-provided"?"No reportada":x.version}</span><strong>{fmt.format(x.count)}</strong></div>)}
      {!ops.versions?.length&&<p className="muted">No hay datos de versión todavía.</p>}
      <p className="muted">Versiones autodeclaradas, no prueba de integridad. Las instalaciones antiguas pueden aparecer como «No reportada».</p>
     </Panel>
     <Panel title="Versiones de formatos VPN" subtitle="Identificadores de versión presentes en metadatos seguros del motor">
      {(ops.formatVersions||[]).filter(x=>x.version!=="not-provided").map(x=>
       <div className="admin-kv" key={x.format+":"+x.version}><span>{x.format} · {x.version}</span><strong>{fmt.format(x.count)}</strong></div>)}
      {!(ops.formatVersions||[]).some(x=>x.version!=="not-provided")&&
       <p className="muted">Los motores actuales no entregan metadatos de versión verificables. Se indicará «No reportada» hasta que estén disponibles.</p>}
     </Panel>
    </div>
   </>}
   <Panel title="Historial de acciones administrativas" subtitle="Reinicios registrados sin cuentas, IP ni identificadores de usuario">
    <div className="admin-table-wrap"><table className="admin-table"><thead><tr>
     <th>Fecha UTC</th><th>Acción</th><th>Ámbito</th><th>Formatos</th>
    </tr></thead><tbody>
     {(ops.actions||[]).slice(0,30).map((a,i)=><tr key={a.at+":"+i}>
      <td>{time(a.at)}</td><td>Reinicio de errores</td><td>{a.scope==="all"?"Todos":a.format}</td><td>{fmt.format(a.formatsReset||0)}</td>
     </tr>)}
     {!ops.actions?.length&&<tr><td colSpan={4}>Sin acciones administrativas recientes.</td></tr>}
    </tbody></table></div>
   </Panel>
  </>}
 </section>;
}
