"use client";
import {useCallback,useEffect,useState} from "react";
import {useRouter} from "next/navigation";
const fmt=new Intl.NumberFormat("es-MX");
const bytes=n=>n<1024?fmt.format(n)+" B":n<1024**2?(n/1024).toFixed(1)+" KiB":(n/1024**2).toFixed(2)+" MiB";
const ErrorMeaning={
  DECODE_FAILED:"Descifrado fallido",ENGINE_TIMEOUT:"Tiempo agotado",
  ENGINE_UNAVAILABLE:"Motor no disponible",AUTH_FAILED:"Autenticación del archivo fallida",
  INVALID_CREDENTIALS:"Credenciales del archivo inválidas",
  PASSWORD_REQUIRED:"Contraseña requerida",HWID_REQUIRED:"HWID requerido",
  HWID_PASSWORD_REQUIRED:"Contraseña y HWID requeridos",
  UNSUPPORTED_FORMAT:"Extensión no soportada",OUTPUT_TOO_LARGE:"Salida demasiado grande",
  INPUT_TOO_LARGE:"Entrada demasiado grande",INVALID_REQUEST:"Solicitud inválida",
  INVALID_BASE64:"Base64 inválido",SERVICE_UNAVAILABLE:"Servicio no disponible",
  OTHER_ERROR:"Otro error del worker"
};
export default function AdminReport({view}){
  const [days,setDays]=useState(7),[report,setReport]=useState(null);
  const [loading,setLoading]=useState(true),[error,setError]=useState("");
  const router=useRouter();
  const refresh=useCallback(async(signal)=>{
    setLoading(true);
    try {
      const response=await fetch("/api/admin/reports?days="+days,
        {cache:"no-store",credentials:"same-origin",signal});
      if(response.status===401){router.replace("/admin/login");return;}
      if(!response.ok)throw Error("No se pudo consultar el informe administrativo ("+response.status+").");
      const data=await response.json();
      if(data.status!=="ok"||!data.report)throw Error("Respuesta inválida del servidor.");
      setReport(data.report);setError("");
    }catch(err){
      if(err.name==="AbortError")return;
      setError(err.message||"No se pudo cargar.");
    }finally{if(!signal?.aborted)setLoading(false);}
  },[days,router]);
  useEffect(()=>{const ac=new AbortController();refresh(ac.signal);return()=>ac.abort();},[refresh]);
  const total=report?.totalDecodes||0;
  const max=Math.max(1,...(report?.daily||[]).map(x=>x.successfulDecodes+x.failedDecodes));
  return <section>
    <div className="admin-report-toolbar">
      <div role="group" aria-label="Rango de consulta" className="admin-range">
        <button type="button" aria-pressed={days===1} onClick={()=>setDays(1)}>Hoy (UTC)</button>
        <button type="button" aria-pressed={days===7} onClick={()=>setDays(7)}>Últimos 7 días</button>
      </div>
      <button className="button subtle" type="button" onClick={()=>refresh()} disabled={loading}>Actualizar</button>
    </div>
    {error&&<div className="form-message error" role="alert">{error}</div>}
    {loading&&<p aria-live="polite" className="muted">Consultando estadísticas…</p>}
    {report&&<>
      <div className="admin-metric-grid" aria-live="polite">
        <article className="admin-card"><span className="muted">Operaciones del worker</span><strong>{fmt.format(total)}</strong></article>
        <article className="admin-card"><span className="muted">Descifrados correctos</span><strong>{fmt.format(report.successfulDecodes)}</strong></article>
        <article className="admin-card"><span className="muted">Descifrados fallidos</span><strong>{fmt.format(report.failedDecodes)}</strong></article>
        <article className="admin-card"><span className="muted">Entrada procesada</span><strong>{bytes(report.inputBytes)}</strong></article>
      </div>
      <p className="muted">Retención: {report.retentionDays} días. Datos desde la instalación de esta telemetría; no incluyen los descifrados anteriores. El consumo indica bytes de entrada procesada, no tráfico total de red ni uso de CPU.</p>
      {view==="analytics"?<>
        <section className="admin-card admin-report-card"><h2>Actividad diaria (UTC)</h2>
          {total===0?<p className="muted">Aún no hay ejecuciones del worker registradas en este periodo.</p>:
          <div className="admin-chart" role="img" aria-label="Descifrados correctos y fallidos por día">
            {report.daily.map(d=><div className="admin-chart-day" key={d.date}>
              <div className="admin-chart-bars" title={d.date+": "+d.successfulDecodes+" correctos, "+d.failedDecodes+" fallidos"}>
                <span className="admin-chart-success" style={{height:Math.max(0,d.successfulDecodes/max*100)+"%"}}/>
                <span className="admin-chart-failed" style={{height:Math.max(0,d.failedDecodes/max*100)+"%"}}/>
              </div>
              <small>{d.date.slice(5)}</small>
            </div>)}
          </div>}
          <p className="muted">Correctos / Fallidos. Los contadores excluyen archivos, contraseñas, IPs y resultados.</p>
        </section>
        <section className="admin-card admin-report-card"><h2>Descifrados por extensión</h2>
          <div className="admin-table-wrap"><table className="admin-table"><thead><tr>
            <th>Formato</th><th>Intentos</th><th>Correctos</th><th>Fallidos</th><th>Éxito</th>
          </tr></thead><tbody>
          {report.extensions.map(f=><tr key={f.extension}>
            <th scope="row">{f.extension==="other"?"Otros / no reconocidos":"."+f.extension}</th>
            <td>{fmt.format(f.attempts)}</td><td>{fmt.format(f.successfulDecodes)}</td>
            <td>{fmt.format(f.failedDecodes)}</td><td>{f.attempts?Math.round(100*f.successfulDecodes/f.attempts)+" %":"—"}</td>
          </tr>)}
          {!report.extensions.length&&<tr><td colSpan={5}>Sin operaciones registradas</td></tr>}
          </tbody></table></div>
        </section>
      </>:<>
        <section className="admin-card admin-report-card"><h2>Extensiones que requieren revisión</h2>
          <p className="muted">Ordenadas por fallos observados en el periodo.</p>
          <div className="admin-table-wrap"><table className="admin-table"><thead><tr><th>Extensión</th><th>Fallidos</th><th>Correctos</th><th>Tasa de fallo</th></tr></thead><tbody>
          {[...report.extensions].filter(f=>f.failedDecodes>0).sort((a,b)=>b.failedDecodes-a.failedDecodes).map(f=><tr key={f.extension}>
            <th scope="row">{f.extension==="other"?"Otros / desconocidos":"."+f.extension}</th>
            <td>{fmt.format(f.failedDecodes)}</td><td>{fmt.format(f.successfulDecodes)}</td>
            <td>{Math.round(f.failedDecodes/f.attempts*100)} %</td></tr>)}
          {!report.extensions.some(f=>f.failedDecodes>0)&&<tr><td colSpan={4}>No hay fallos registrados</td></tr>}
          </tbody></table></div>
        </section>
        <section className="admin-card admin-report-card"><h2>Motivos de error</h2>
          <div className="admin-table-wrap"><table className="admin-table"><thead><tr><th>Motivo</th><th>Código</th><th>Casos</th></tr></thead><tbody>
          {report.errors.map(e=><tr key={e.code}><td>{ErrorMeaning[e.code]||e.code.replaceAll("_"," ")}</td><td><code>{e.code}</code></td><td>{fmt.format(e.count)}</td></tr>)}
          {!report.errors.length&&<tr><td colSpan={3}>Sin errores</td></tr>}
          </tbody></table></div>
        </section>
        <section className="admin-card admin-report-card"><h2>Fallos específicos por extensión</h2>
          <div className="admin-table-wrap"><table className="admin-table"><thead><tr><th>Extensión</th><th>Error</th><th>Casos</th></tr></thead><tbody>
          {report.incidents.map((e,i)=><tr key={e.extension+":"+e.code+":"+i}><td>{e.extension}</td><td>{ErrorMeaning[e.code]||e.code}</td><td>{fmt.format(e.count)}</td></tr>)}
          {!report.incidents.length&&<tr><td colSpan={3}>Sin incidencias</td></tr>}
          </tbody></table></div>
        </section>
      </>}
    </>}
  </section>;
}
