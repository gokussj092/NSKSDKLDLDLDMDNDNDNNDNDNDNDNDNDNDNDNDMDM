"use client";
import {useEffect,useState} from 'react';
import {useRouter} from 'next/navigation';
const actions={staff_created:'Personal creado',staff_updated:'Personal actualizado',
 staff_password_changed:'Contraseña modificada',support_assigned:'Ticket asignado',
 customer_viewed:'Ficha de cliente consultada',support_reply:'Respuesta de soporte',
 support_close:'Ticket cerrado',support_reopen:'Ticket reabierto'};
export default function StaffAudit(){
 const router=useRouter(),[events,setEvents]=useState([]),[error,setError]=useState('');
 useEffect(()=>{let mounted=true;
  fetch('/api/admin/staff-audit',{cache:'no-store'}).then(async r=>{
    if(r.status===401){router.replace('/admin/login');return;}
    if(!r.ok)throw Error('No se pudo consultar el registro de auditoría.');
    const data=await r.json();if(mounted)setEvents(data.events||[]);
  }).catch(e=>{if(mounted)setError(e.message)});
  return()=>{mounted=false};
 },[router]);
 return <section className="admin-card"><h2>Últimas acciones del equipo</h2>
  <p className="muted">Registro de operaciones sobre personal, soporte y consulta de cuentas. Solo usuarios autorizados.</p>
  {error&&<p className="form-message error" role="alert">{error}</p>}
  <div className="sp-admin-table-wrap"><table className="sp-admin-directory-table">
   <thead><tr><th>Acción</th><th>Operador</th><th>Cargo</th><th>Destino</th><th>Fecha</th></tr></thead>
   <tbody>{events.map((x,i)=><tr key={i}><td>{actions[x.action]||x.action}</td>
    <td><code>{x.actor_id}</code></td><td>{x.actor_role}</td>
    <td><code>{x.target_id}</code></td>
    <td>{new Date(x.created_at).toLocaleString('es-MX')}</td></tr>)}</tbody>
  </table></div>
  {!events.length&&!error&&<p className="muted">No se registraron acciones recientes.</p>}
 </section>;
