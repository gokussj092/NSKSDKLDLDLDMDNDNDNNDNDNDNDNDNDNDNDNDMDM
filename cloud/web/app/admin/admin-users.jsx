"use client";
import {useCallback,useEffect,useState} from 'react';
import {useRouter} from 'next/navigation';
function date(value){return value?new Date(value).toLocaleString('es-MX',{dateStyle:'medium',timeStyle:'short'}):'—';}
function avatar(value){
 if(typeof value!=='string')return null;
 if(/^https:\/\/lh[3-6]\.googleusercontent\.com\//.test(value))return value;
 if(/^data:image\/jpeg;base64,[A-Za-z0-9+/]+={0,2}$/.test(value)&&value.length<115000)return value;
 return null;
}
function PersonAvatar({user}){
 return avatar(user.avatar)?<img src={avatar(user.avatar)} alt="" className="sp-person-avatar" width="44" height="44"/>:
 <span className="sp-person-avatar" aria-hidden="true">{user.name?.slice(0,1)||'?'}</span>;
}
function Detail({data,onBack}){
 const {user,identities,orders,entitlements,redemptions,tickets,sessions,creditMovements}=data;
 return <section className="admin-card sp-customer-detail">
  <button className="button" onClick={onBack}>Volver al directorio</button>
  <div className="sp-customer-identity"><PersonAvatar user={user}/>
   <div><h2>{user.name}</h2><p>{user.username?'@'+user.username:'Sin usuario personalizado'}</p>
    <p>{user.email}</p><small className="muted">ID permanente: {user.id}</small></div>
  </div>
  <div className="sp-customer-stat-grid">
   <div><small>Alta</small><strong>{date(user.created_at)}</strong></div>
   <div><small>Última actividad</small><strong>{date(sessions?.last_active)}</strong></div>
   <div><small>Sesiones activas</small><strong>{sessions?.total||0}</strong></div>
   <div><small>Proveedor de acceso</small><strong>{identities.map(i=>i.provider_id).join(', ')||'—'}</strong></div>
  </div>
  <p className="muted">Los secretos OAuth, hashes de contraseña, tokens de sesión y claves API nunca se muestran en este panel.</p>
  <section><h2>Pedidos y pagos</h2>{!orders.length?<p className="muted">Sin pedidos.</p>:
   <div className="sp-admin-table-wrap"><table className="sp-admin-directory-table"><thead><tr><th>Producto</th><th>Estado</th><th>Proveedor</th><th>Total</th><th>Fecha</th></tr></thead>
    <tbody>{orders.map(x=><tr key={x.id}><td>{x.product_id}</td><td>{x.status}</td><td>{x.provider}</td>
     <td>{x.quote?.total!=null?x.quote.total+' '+(x.quote.currency||'USD'):'—'}</td><td>{date(x.created_at)}</td></tr>)}</tbody></table></div>}</section>
  <section><h2>Licencias y servicios</h2>{!entitlements.length?<p className="muted">Sin licencias.</p>:<div className="sp-admin-table-wrap"><table className="sp-admin-directory-table"><thead><tr><th>Servicio</th><th>Estado</th><th>Vence</th><th>IP autorizada</th></tr></thead><tbody>{entitlements.map(x=><tr key={x.id}><td>{x.product_id}</td><td>{x.status}</td><td>{date(x.expires_at)}</td><td>{x.allowed_ip||'—'}</td></tr>)}</tbody></table></div>}</section>
  <section><h2>Códigos canjeados</h2>{!redemptions.length?<p className="muted">Sin canjes.</p>:<div className="sp-customer-tags">{redemptions.map((x,i)=><span key={i}>{x.title} · {date(x.created_at)}</span>)}</div>}</section>
  <section><h2>Soporte</h2>{!tickets.length?<p className="muted">Sin conversaciones.</p>:<div className="sp-customer-tags">{tickets.map(t=><span key={t.id}>{t.subject} · {t.status}</span>)}</div>}</section>
  <section><h2>Movimientos de créditos</h2>{!creditMovements.length?<p className="muted">Sin movimientos.</p>:<div className="sp-customer-tags">{creditMovements.map((x,i)=><span key={i}>{x.movement_kind} {x.delta>0?'+':''}{x.delta} · {date(x.created_at)}</span>)}</div>}</section>
 </section>;
}
export default function AdminUsers(){
 const router=useRouter();
 const [q,setQ]=useState(''),[filter,setFilter]=useState(''),[page,setPage]=useState(0),
 [result,setResult]=useState({users:[],count:0,pageSize:30}),[detail,setDetail]=useState(null),
 [loading,setLoading]=useState(false),[error,setError]=useState('');
 const load=useCallback(async()=>{
  setLoading(true);setError('');
  try{
   const params=new URLSearchParams({page:String(page),q:filter});
   const response=await fetch('/api/admin/users?'+params,{cache:'no-store',credentials:'same-origin'});
   if(response.status===401){router.replace('/admin/login');return;}
   if(!response.ok)throw Error('No se pudo cargar el directorio.');
   setResult(await response.json());
  }catch(e){setError(e.message);}finally{setLoading(false);}
 },[filter,page,router]);
 useEffect(()=>{load();},[load]);
 async function openUser(id){
  setLoading(true);setError('');
  try{
   const r=await fetch('/api/admin/users?id='+encodeURIComponent(id),{cache:'no-store',credentials:'same-origin'});
   if(!r.ok)throw Error('No se pudo consultar la cuenta.');
   setDetail(await r.json());
  }catch(e){setError(e.message);}finally{setLoading(false);}
 }
 return <div className="sp-admin-commerce">
  <section className="sp-admin-commerce-hero"><div><span className="sp-admin-commercial-kicker">CUENTAS · CLIENTES</span>
   <h2>Usuarios registrados</h2><p>Directorio de cuentas, compras, licencias, créditos y atención recibida.</p>
  </div></section>
  {error&&<p className="form-message error" role="alert">{error}</p>}
  {detail?<Detail data={detail} onBack={()=>setDetail(null)}/>:<>
   <section className="admin-card">
    <form className="sp-directory-search" onSubmit={e=>{e.preventDefault();setPage(0);setFilter(q.trim());}}>
     <label htmlFor="sp-user-filter">Buscar por nombre, correo, usuario o ID</label>
     <div><input id="sp-user-filter" maxLength={80} value={q} placeholder="Buscar cuenta…" onChange={e=>setQ(e.target.value)}/>
      <button className="button primary" type="submit" disabled={loading}>Buscar</button></div>
    </form>
    <div className="sp-directory-summary"><strong>{result.count||0} cuentas</strong><small className="muted">Página {page+1} · {result.pageSize} por página</small></div>
    <div className="sp-admin-table-wrap"><table className="sp-admin-directory-table">
     <thead><tr><th>Usuario</th><th>Correo</th><th>Registro</th><th>Créditos</th><th>Sin anuncios</th><th>Soporte</th><th></th></tr></thead>
     <tbody>{result.users?.map(user=><tr key={user.id}>
      <td><div className="sp-directory-person"><PersonAvatar user={user}/><div><strong>{user.name}</strong><small>{user.username?'@'+user.username:'Sin @usuario'}</small></div></div></td>
      <td>{user.email}</td><td>{date(user.created_at)}</td><td>{user.credits}</td>
      <td>{user.ad_free?'Activo':'—'}</td><td>{user.open_tickets}</td>
      <td><button className="button" disabled={loading} onClick={()=>openUser(user.id)}>Ver perfil</button></td>
     </tr>)}</tbody></table></div>
    {!result.users?.length&&<p className="muted">No hay usuarios que coincidan con la búsqueda.</p>}
    <div className="sp-directory-pages">
     <button className="button" disabled={page===0||loading} onClick={()=>setPage(x=>x-1)}>Anterior</button>
     <button className="button" disabled={(page+1)*result.pageSize>=result.count||loading} onClick={()=>setPage(x=>x+1)}>Siguiente</button>
    </div>
   </section>
  </>}
 </div>;
}
