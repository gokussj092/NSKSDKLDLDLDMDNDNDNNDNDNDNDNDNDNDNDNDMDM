"use client";
import {useCallback,useEffect,useState} from 'react';
import {useRouter} from 'next/navigation';
// Panel de testers de la prueba cerrada de Google Play. Sigue el patrón de
// admin-app-analysis.jsx: fetch con credentials same-origin, refresco cada
// 15 s, errorText con códigos, fechas es-MX. SOLO LECTURA: la lista muestra
// quién instaló desde Play, con qué versión, desde cuándo y cuántos días
// usó la app en su ventana de 14 días. NO hay entrega automática: Pedro
// otorga créditos / mes sin anuncios A MANO, fuera de este panel.
// Un tester "califica" si instaló desde Play y usó la app al menos una vez
// en su ventana; no se exige uso diario.
const SOURCE={play:'Google Play',other:'Otra fuente',unknown:'Sin datos'};
function fullDate(value){
 const d=new Date(value);
 if(Number.isNaN(d.getTime()))return '—';
 return d.toLocaleString('es-MX',{day:'2-digit',month:'short',year:'numeric',
  hour:'2-digit',minute:'2-digit'});
}
function shortDate(value){
 if(!value)return '—';
 const d=new Date(value+'T12:00:00Z');
 if(Number.isNaN(d.getTime()))return '—';
 return d.toLocaleDateString('es-MX',{day:'2-digit',month:'short',year:'numeric'});
}
function errorText(data,status,fallback){
 const code=data?.error?.code;
 if(code==='FORBIDDEN'||status===403)return 'No tienes permiso para realizar esta acción.';
 if(code==='UNAUTHORIZED'||status===401)return 'Tu sesión expiró. Vuelve a iniciar sesión.';
 return fallback;
}
export default function AdminPlayTesters(){
 const router=useRouter();
 const [testers,setTesters]=useState([]),[filter,setFilter]=useState('all'),
  [loading,setLoading]=useState(true),[loadError,setLoadError]=useState('');
 const load=useCallback(async()=>{
  const r=await fetch('/api/admin/play-testers',{credentials:'same-origin',cache:'no-store'});
  if(r.status===401){router.replace('/admin/login');return;}
  if(!r.ok){
   const data=await r.json().catch(()=>null);
   throw Error(errorText(data,r.status,'No se pudieron cargar los testers.'));
  }
  const payload=await r.json();
  setTesters(payload.testers||[]);
  setLoadError('');
 },[router]);
 useEffect(()=>{setLoading(true);load().catch(e=>setLoadError(e.message))
   .finally(()=>setLoading(false));
  const t=setInterval(()=>load().catch(()=>{}),15000);
  return()=>clearInterval(t);},[load]);
 const shown=testers.filter(t=>filter==='all'?true:
  filter==='qualified'?t.qualifies:t.installSource===filter);
 const qualified=testers.filter(t=>t.qualifies).length;
 return <div className="sp-admin-commerce sp-app-analysis-admin">
  <header className="sp-admin-commerce-hero"><div>
   <span className="sp-admin-commercial-kicker">SP-DECODE · PRUEBA CERRADA GOOGLE PLAY</span>
   <p className="muted">Testers detectados por el servidor: origen de instalación
    y versión de la primera vez que se vio la app (no se sobrescribe), y días
    con uso dentro de la ventana de 14 días desde su primer día activo.
    Califica quien instaló desde Play y usó la app al menos una vez en su
    ventana — no se exige uso diario. Las recompensas se otorgan A MANO:
    este panel solo cuenta y muestra, no entrega nada.</p>
  </div></header>
  <section className="admin-card"><h2>Testers ({testers.length}) · Califican: {qualified}</h2>
   <div className="sp-chat-filters">
    {[['all','Todos ('+testers.length+')'],['qualified','Califican ('+qualified+')'],
      ['play','Google Play ('+testers.filter(t=>t.installSource==='play').length+')'],
      ['other','Otra fuente ('+testers.filter(t=>t.installSource==='other').length+')'],
      ['unknown','Sin datos ('+testers.filter(t=>t.installSource==='unknown').length+')']]
     .map(([key,label])=>
      <button key={key} type="button" className={filter===key?'current':''}
       onClick={()=>setFilter(key)}>{label}</button>)}
   </div>
   {loading?<p className="muted" role="status">Cargando testers…</p>
    :loadError?<p className="form-message error" role="alert">{loadError}</p>
    :!shown.length?<p className="muted">Todavía no hay testers en este filtro.</p>:
    <div className="admin-table-wrap"><table className="admin-table">
     <thead><tr><th>Cuenta</th><th>Instalado desde</th><th>Versión</th>
      <th>Primera vez visto</th><th>Ventana de 14 días</th><th>Días usados</th>
      <th>Califica</th></tr></thead>
     <tbody>{shown.map(t=><tr key={t.accountId}>
      <td><code>{t.accountId}</code>
       {t.deviceKeyHash&&<div className="muted">dispositivo {t.deviceKeyHash.slice(0,12)}…</div>}</td>
      <td><strong>{SOURCE[t.installSource]||t.installSource}</strong>
       {t.installerPackage&&<div className="muted">{t.installerPackage}</div>}</td>
      <td>{t.versionName||'—'}
       {t.versionCode!==null&&t.versionCode!==undefined&&
        <div className="muted">code {t.versionCode}</div>}</td>
      <td>{fullDate(t.firstSeenAt)}</td>
      <td>{shortDate(t.windowStart)} — {shortDate(t.windowEnd)}
       {t.lastActiveDay&&<div className="muted">último uso {shortDate(t.lastActiveDay)}</div>}</td>
      <td><strong>{t.activeDays}</strong> de 14</td>
      <td>{t.qualifies?<strong>Sí</strong>:'No'}</td>
     </tr>)}</tbody>
    </table></div>}
  </section>
 </div>;
}
