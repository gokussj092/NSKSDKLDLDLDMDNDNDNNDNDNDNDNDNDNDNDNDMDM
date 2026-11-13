"use client";
import {useCallback,useEffect,useState} from 'react';
import {useRouter} from 'next/navigation';
const labels={admin:'Administrador',support:'Soporte técnico',moderator:'Moderación',billing:'Facturación'};
const initial={name:'',username:'',role:'support'};
const canName=value=>value?.trim()?.length>=2;
function StaffRow({row,onSave,onReset,busy}){
 const [edit,setEdit]=useState({name:row.name,username:row.username,role:row.role,enabled:row.enabled});
 useEffect(()=>{setEdit({name:row.name,username:row.username,role:row.role,enabled:row.enabled});},[row.id,row.updatedAt]);
 return <article className="sp-personnel-row">
  <div className="sp-person-avatar" aria-hidden="true">{row.name?.slice(0,1)?.toUpperCase()||'S'}</div>
  <div className="sp-person-fields">
   <label>Nombre<input value={edit.name} maxLength={80} onChange={e=>setEdit(x=>({...x,name:e.target.value}))}/></label>
   <label>Usuario<input value={edit.username} maxLength={48} onChange={e=>setEdit(x=>({...x,username:e.target.value.toLowerCase()}))}/></label>
   <label>Cargo<select value={edit.role} onChange={e=>setEdit(x=>({...x,role:e.target.value}))}>
    {Object.entries(labels).map(([v,name])=><option key={v} value={v}>{name}</option>)}</select></label>
   <label className="sp-person-check"><input type="checkbox" checked={edit.enabled} onChange={e=>setEdit(x=>({...x,enabled:e.target.checked}))}/> Cuenta habilitada</label>
  </div>
  <div className="sp-person-actions">
   <small className="muted">Último acceso: {row.lastLoginAt?new Date(row.lastLoginAt).toLocaleString('es-MX'):'Sin accesos'}</small>
   <small className="muted">{row.mustChangePassword?'Cambio de contraseña pendiente':'Credencial configurada'}</small>
   <div className="sp-action-group">
    <button className="button primary" disabled={busy||!canName(edit.name)} onClick={()=>onSave({id:row.id,...edit})}>Guardar</button>
    <button className="button" disabled={busy} onClick={()=>onReset(row)}>Restablecer contraseña</button>
   </div>
  </div>
 </article>;
}
export default function StaffAdmin(){
 const router=useRouter(),[rows,setRows]=useState([]),[form,setForm]=useState(initial),
 [secret,setSecret]=useState(null),[busy,setBusy]=useState(false),
 [error,setError]=useState(''),[notice,setNotice]=useState(''),[access,setAccess]=useState(null);
 const load=useCallback(async()=>{
  const [auth,staff]=await Promise.all([fetch('/api/admin/access',{cache:'no-store'}),
    fetch('/api/admin/staff',{cache:'no-store'})]);
  if(auth.status===401){router.replace('/admin/login');return;}
  if(!auth.ok||!staff.ok)throw Error('Acceso restringido a la gestión de personal.');
  setAccess((await auth.json()).principal);setRows((await staff.json()).staff||[]);
 },[router]);
 useEffect(()=>{load().catch(e=>setError(e.message));},[load]);
 async function mutate(body){
  setBusy(true);setError('');setNotice('');
  try{
   const response=await fetch('/api/admin/staff',{method:'POST',credentials:'same-origin',
    headers:{'Content-Type':'application/json','X-SPDecode-Admin-Action':'1'},body:JSON.stringify(body)});
   const data=await response.json();
   if(!response.ok)throw Error(data.error?.code==='STAFF_USERNAME_TAKEN'?'Ese usuario ya existe.':
     'No se pudo guardar. Comprueba los permisos y los datos.');
   if(data.temporaryPassword)setSecret({username:data.staff.username,password:data.temporaryPassword});
   setNotice(body.action==='create'?'Cuenta creada. Entrega las credenciales de forma privada.':'Cambios guardados y sesiones anteriores revocadas.');
   if(body.action==='create')setForm(initial);
   await load();
  }catch(e){setError(e.message);}finally{setBusy(false);}
 }
 function resetPassword(row){
  if(!window.confirm('Se revocarán las sesiones de '+row.username+'. ¿Generar nueva contraseña temporal?'))return;
  mutate({action:'update',id:row.id,resetPassword:true});
 }
 return <div className="sp-admin-commerce">
  <section className="sp-admin-commerce-hero"><div><span className="sp-admin-commercial-kicker">SEGURIDAD · PERSONAL</span>
   <h2>Gestión del equipo</h2><p>Cuentas independientes y permisos por cargo. La cuenta propietaria del VPS no se comparte.</p>
  </div></section>
  {error&&<p className="form-message error" role="alert">{error}</p>}
  {notice&&<p className="form-message" role="status">{notice}</p>}
  {secret&&<section className="admin-card sp-secret-once" role="status">
   <h2>Credenciales temporales — visibles una sola vez</h2>
   <p className="muted">La contraseña no podrá consultarse después. Envía las credenciales por un canal seguro; se exigirá reemplazarlas en el primer ingreso.</p>
   <p><strong>Usuario:</strong> <code>{secret.username}</code></p>
   <p><strong>Contraseña:</strong> <code>{secret.password}</code></p>
   <div className="sp-action-group"><button className="button" onClick={()=>navigator.clipboard.writeText('Usuario: '+secret.username+'\nContraseña: '+secret.password)}>Copiar credenciales</button>
    <button className="button primary" onClick={()=>setSecret(null)}>Ocultar permanentemente</button></div>
  </section>}
  {access?.role==='owner'&&<section className="admin-card"><h2>Agregar miembro</h2>
   <form className="sp-staff-create" onSubmit={e=>{e.preventDefault();mutate({action:'create',...form});}}>
    <label>Nombre visible<input required minLength={2} maxLength={80} value={form.name} onChange={e=>setForm(x=>({...x,name:e.target.value}))}/></label>
    <label>Usuario único<input required pattern="[a-z][a-z0-9._-]{2,47}" maxLength={48} value={form.username} onChange={e=>setForm(x=>({...x,username:e.target.value.toLowerCase()}))}/></label>
    <label>Cargo<select value={form.role} onChange={e=>setForm(x=>({...x,role:e.target.value}))}>
     {Object.entries(labels).map(([v,name])=><option value={v} key={v}>{name}</option>)}</select></label>
    <button className="button primary" type="submit" disabled={busy||!canName(form.name)}>Crear usuario y contraseña</button>
   </form>
  </section>}
  <section className="admin-card"><h2>Personal autorizado</h2>
   <p className="muted">Al editar credenciales, estado o cargo se invalidan todas las sesiones anteriores.</p>
   {!rows.length?<p className="muted">No hay integrantes registrados.</p>:
    <div className="sp-personnel-list">{rows.map(row=><StaffRow key={row.id} row={row}
      busy={busy||access?.role!=='owner'}
      onSave={values=>mutate({action:'update',...values})} onReset={resetPassword}/>)}</div>}
  </section>
 </div>;
}