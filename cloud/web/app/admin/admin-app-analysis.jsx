"use client";
import {useCallback,useEffect,useState} from 'react';
import {useRouter} from 'next/navigation';
// Panel mínimo de análisis de APK (SP-DECODE Arnés, fase 1). Sigue el patrón
// de admin-support.jsx: fetch con credentials same-origin, refresco cada
// 15 s, errorText con códigos, fechas es-MX. La revisión de candidatos solo
// cambia pending -> approved/rejected; la promoción al catálogo público es
// manual (Pedro) y queda fuera de este panel.
const STATUS={UPLOADING:'Subiendo',UPLOADED:'Recibido',QUEUED_FOR_ANALYSIS:'En cola',
 ANALYZING:'Analizando',AWAITING_HUMAN:'En revisión',COMPLETED:'Completado',
 COMPLETED_PARTIAL:'Completado (parcial)',FAILED:'Fallido',REJECTED:'Rechazado',
 EXPIRED:'Caducado'};
const CANDIDATE={pending:'Pendiente',approved:'Aprobado',rejected:'Rechazado',
 published:'Publicado'};
function fullDate(value){
 const d=new Date(value);
 if(Number.isNaN(d.getTime()))return '—';
 return d.toLocaleString('es-MX',{day:'2-digit',month:'short',year:'numeric',
  hour:'2-digit',minute:'2-digit'});
}
function errorText(data,status,fallback){
 const code=data?.error?.code;
 if(code==='FORBIDDEN'||status===403)return 'No tienes permiso para realizar esta acción.';
 if(code==='UNAUTHORIZED'||status===401)return 'Tu sesión expiró. Vuelve a iniciar sesión.';
 if(code==='APP_ANALYSIS_CANDIDATE_REVIEWED'||status===409)
  return 'Ese candidato ya fue revisado.';
 if(code==='APP_ANALYSIS_CANDIDATE_NOT_FOUND'||status===404)
  return 'El candidato ya no existe. Recarga el panel.';
 return fallback;
}
export default function AdminAppAnalysis(){
 const router=useRouter();
 const [jobs,setJobs]=useState([]),[candidates,setCandidates]=useState([]),
  [filter,setFilter]=useState('all'),[loading,setLoading]=useState(true),
  [loadError,setLoadError]=useState(''),[error,setError]=useState(''),
  [notice,setNotice]=useState(''),[busy,setBusy]=useState(false);
 const load=useCallback(async()=>{
  const url=filter==='all'?'/api/admin/app-analysis':
    '/api/admin/app-analysis?status='+encodeURIComponent(filter);
  const r=await fetch(url,{credentials:'same-origin',cache:'no-store'});
  if(r.status===401){router.replace('/admin/login');return;}
  if(!r.ok){
   const data=await r.json().catch(()=>null);
   throw Error(errorText(data,r.status,'No se pudieron cargar los análisis.'));
  }
  const payload=await r.json();
  setJobs(payload.jobs||[]);setCandidates(payload.candidates||[]);
  setLoadError('');
 },[router,filter]);
 useEffect(()=>{setLoading(true);load().catch(e=>setLoadError(e.message))
   .finally(()=>setLoading(false));
  const t=setInterval(()=>load().catch(()=>{}),15000);
  return()=>clearInterval(t);},[load]);
 async function review(candidateId,decision){
  if(!window.confirm(decision==='approved'
    ?'¿Aprobar este candidato de catálogo? La publicación sigue siendo manual.'
    :'¿Rechazar este candidato de catálogo?'))return;
  setBusy(true);setError('');setNotice('');
  try{
   const r=await fetch('/api/admin/app-analysis',{method:'POST',cache:'no-store',
     credentials:'same-origin',
     headers:{'Content-Type':'application/json','X-SPDecode-Admin-Action':'1'},
     body:JSON.stringify({action:'reviewCandidate',candidateId,decision})});
   if(!r.ok){
    const data=await r.json().catch(()=>null);
    throw Error(errorText(data,r.status,'No se pudo revisar el candidato.'));
   }
   setNotice(decision==='approved'?'Candidato aprobado. La promoción al catálogo es manual.':
     'Candidato rechazado.');
   await load();
  }catch(e){setError(e.message);}
  finally{setBusy(false);}
 }
 const counts=jobs.reduce((acc,j)=>{acc[j.status]=(acc[j.status]||0)+1;return acc;},{});
 return <div className="sp-admin-commerce sp-app-analysis-admin">
  <header className="sp-admin-commerce-hero"><div>
   <span className="sp-admin-commercial-kicker">SP-DECODE · ANÁLISIS DE APK</span>
   <p className="muted">Trabajos de SP-DECODE Arnés: estado, cuenta, paquete, progreso y
    crédito. La cola es FIFO; solo 1 análisis a la vez por defecto
    (SPDECODE_APP_ANALYSIS_MAX_CONCURRENT). El icono del candidato nunca se
    muestra ni se descarga desde aquí: queda en el área privada hasta que
    Pedro apruebe publicarlo.</p>
  </div></header>
  {error&&<p className="form-message error" role="alert">{error}</p>}
  {notice&&<p className="form-message" role="status">{notice}</p>}
  <section className="admin-card"><h2>Trabajos de análisis</h2>
   <div className="sp-chat-filters">
    {['all',...Object.keys(STATUS)].map(key=>
     <button key={key} type="button" className={filter===key?'current':''}
      onClick={()=>setFilter(key)}>{key==='all'?'Todos ('+jobs.length+')':
       (STATUS[key]||key)+' ('+(counts[key]||0)+')'}</button>)}
   </div>
   {loading?<p className="muted" role="status">Cargando trabajos…</p>
    :loadError?<p className="form-message error" role="alert">{loadError}</p>
    :!jobs.length?<p className="muted">Todavía no hay trabajos de análisis.</p>:
    <div className="admin-table-wrap"><table className="admin-table">
     <thead><tr><th>Estado</th><th>Cuenta</th><th>Paquete</th><th>Progreso</th>
      <th>Crédito</th><th>Creado</th></tr></thead>
     <tbody>{jobs.map(job=><tr key={job.jobId}>
      <td><strong>{STATUS[job.status]||job.status}</strong>
       {job.errorCode&&<div className="muted">{job.errorCode}</div>}
       {job.phaseCode&&<div className="muted">{job.phaseCode}</div>}</td>
      <td><code>{job.accountId}</code></td>
      <td>{job.packageName||job.appName||job.filename}
       <div className="muted">{job.filename}</div></td>
      <td>{job.progressPercent===null||job.progressPercent===undefined
        ?(job.receivedBytes||0)+' / '+(job.totalBytes||0)+' B'
        :job.progressPercent+'%'}</td>
      <td>{job.creditState}</td>
      <td>{fullDate(job.createdAt)}</td>
     </tr>)}</tbody>
    </table></div>}
  </section>
  <section className="admin-card"><h2>Candidatos de catálogo</h2>
   <p className="muted">Métodos nuevos guardados con la entrega al usuario.
    Aprobar o rechazar solo cambia el estado; nada se publica solo.</p>
   {!candidates.length?<p className="muted">No hay candidatos pendientes de revisión.</p>:
    <div className="admin-table-wrap"><table className="admin-table">
     <thead><tr><th>Proveedor</th><th>Paquete</th><th>Estado</th><th>Artefactos</th>
      <th>Revisado</th><th>Acción</th></tr></thead>
     <tbody>{candidates.map(c=><tr key={c.id}>
      <td><strong>{c.providerId}</strong><div className="muted">{c.jobId}</div></td>
      <td>{c.packageName||c.appName||'—'}<div className="muted">{c.jobStatus}</div></td>
      <td>{CANDIDATE[c.status]||c.status}</td>
      <td>{[c.hasIcon?'Icono':'',c.hasCatalog?'Catálogo':'',
        c.hasTexts?'Textos':''].filter(Boolean).join(' · ')||'—'}</td>
      <td>{c.reviewedBy?fullDate(c.reviewedAt):'—'}</td>
      <td>{c.status==='pending'&&<>
       <button type="button" className="button" disabled={busy}
        onClick={()=>review(c.id,'approved')}>Aprobar</button>{' '}
       <button type="button" className="button" disabled={busy}
        onClick={()=>review(c.id,'rejected')}>Rechazar</button></>}</td>
     </tr>)}</tbody>
    </table></div>}
  </section>
 </div>;
}
