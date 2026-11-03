"use client";
const fmt=new Intl.NumberFormat("es-MX");
function Counts({values}){
 const rows=Object.entries(values||{}).sort((a,b)=>b[1]-a[1]);
 return rows.length?<div className="sp-admin-attestation-rows">{rows.map(([name,count])=>
  <div className="sp-admin-attestation-row" key={name}><code>{name}</code><strong>{fmt.format(count)}</strong></div>)}</div>:
  <p className="muted">Sin eventos registrados en este período.</p>;
}
function Totals({data}){return <p>
 Aceptadas: <strong>{data.accepted===null?"Desconocido":fmt.format(data.accepted)}</strong> ·
 Rechazadas: <strong>{fmt.format(data.rejected)}</strong> ·
 Tasa de rechazo: <strong>{data.rejectionPercent===null?"Sin denominador disponible":data.rejectionPercent+" %"}</strong>
 </p>;}
export default function AdminV2Diagnostics({hardware,play}){
 return <section className="sp-admin-attestation-stats" aria-label="Diagnóstico agregado de admisión">
  <h3>Diagnóstico de atestación de hardware</h3>
  <p className="muted">Intentos de verificación desde el arranque del servicio. Un teléfono puede generar varios intentos.
   Las claves ya registradas reutilizan su atestación; estos números no representan a todos los usuarios.</p>
  {hardware?<><p className="muted">Tiempo activo: {Math.floor(hardware.uptimeSeconds/3600)} horas.
    Datos consultados: {new Date(hardware.updatedAt).toLocaleString("es-MX")}</p>
   <Totals data={hardware}/><h4>Motivos de rechazo</h4><Counts values={hardware.rejections}/>
   <h4>Señales observadas (pueden coincidir en un intento)</h4><Counts values={hardware.observations}/>
   <h4>Detalle de CERT_PATH</h4><Counts values={hardware.certificatePathReasons}/>
  </>:<p className="muted">Métricas no disponibles. Comprueba el servicio de atestación.</p>}
  <h3>Admisión V2 y señales de Play</h3>
  <p className="muted">Sesiones aceptadas o rechazadas hoy (UTC), con independencia del modo de Play.
   Las señales observadas se cuentan por separado y pueden coincidir; no se suman como rechazos.</p>
  {play?<><Totals data={play}/><p className="muted">Fecha UTC: {play.date}.</p>
    <Counts values={play.counts}/></>:<p className="muted">Datos no disponibles.</p>}
  <p className="muted">Root: desconocido. Ninguna ausencia de señal demuestra que un dispositivo esté libre de root.
   Se muestran contadores agregados, sin claves, certificados, IP ni identificadores de usuarios.</p>
 </section>;
}
