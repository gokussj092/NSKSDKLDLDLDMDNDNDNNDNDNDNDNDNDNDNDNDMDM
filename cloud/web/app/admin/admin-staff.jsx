"use client";
import {useCallback,useEffect,useState} from 'react';
import {useRouter} from 'next/navigation';
const labels={admin:'Administrador',support:'Soporte técnico',moderator:'Moderación',billing:'Facturación'};
const initial={name:'',username:'',role:'support'};
const PERMISSION_NAMES={
 'users.read':'Ver usuarios',
 'support.read':'Ver conversaciones',
 'support.write':'Responder soporte',
 'support.assign':'Asignar conversaciones',
 'billing.read':'Consultar compras'
};
function CustomRoleRow({row,busy,onSave}){
 const [name,setName]=useState(row.name),[enabled,setEnabled]=useState(row.enabled),
 [permissions,setPermissions]=useState(row.permissions);
 useEffect(()=>{setName(row.name);setEnabled(row.enabled);setPermissions(row.permissions);},
  [row.code,row.updated_at]);
 return <div className="sp-personnel-row">
  <div className="sp-person-fields">
   <h3>{row.code}</h3>
   <label>Nombre<input value={name} maxLength={72} onChange={e=>setName(e.target.value)}/></label>
   <label><input type="checkbox" checked={enabled} onChange={e=>setEnabled(e.target.checked)}/> Habilitado</label>
   <fieldset><legend>Permisos autorizados</legend>
    {Object.entries(PERMISSION_NAMES).map(([key,label])=><label key={key}>
     <input type="checkbox" checked={permissions.includes(key)}
      onChange={e=>setPermissions(v=>e.target.checked?[...v,key]:v.filter(x=>x!==key))}/>
     {label}</label>)}
   </fieldset>
   <button className="button primary" type="button" disabled={busy||name.trim().length<3}
    onClick={()=>onSave({action:'update',code:row.code,name,enabled,permissions})}>
    Guardar permisos</button>
  </div>
 </div>;
}

const canName=value=>value?.trim()?.length>=2;
// Avatar de personal: misma regla que el servidor (data-URI JPEG ≤ 85 KB).
const MAX_AVATAR_URI=115000;
function avatarOk(src){
 if(typeof src!=='string')return null;
 if(/^data:image\/jpeg;base64,[A-Za-z0-9+/]+={0,2}$/.test(src)&&src.length<=MAX_AVATAR_URI)return src;
 return null;
}
function fileToJpegDataUri(file){
 return new Promise((resolve,reject)=>{
  const url=URL.createObjectURL(file);
  const img=new Image();
  img.onload=()=>{
   URL.revokeObjectURL(url);
   const maxSide=512,scale=Math.min(1,maxSide/Math.max(img.width,img.height));
   const canvas=document.createElement('canvas');
   canvas.width=Math.max(1,Math.round(img.width*scale));
   canvas.height=Math.max(1,Math.round(img.height*scale));
   const ctx=canvas.getContext('2d');
   ctx.fillStyle='#000';ctx.fillRect(0,0,canvas.width,canvas.height);
   ctx.drawImage(img,0,0,canvas.width,canvas.height);
   let quality=0.85,uri=canvas.toDataURL('image/jpeg',quality);
   while(uri.length>MAX_AVATAR_URI&&quality>0.5){quality-=0.1;uri=canvas.toDataURL('image/jpeg',quality);}
   resolve(uri);
  };
  img.onerror=()=>{URL.revokeObjectURL(url);reject(new Error('Imagen no válida'));};
  img.src=url;
 });
}
function AvatarField({value,name,onChange,busy}){
 const [error,setError]=useState(''),[paste,setPaste]=useState('');
 const apply=uri=>{
  if(!avatarOk(uri)){setError('Pega un data-URI JPEG válido de 85 KB o menos.');return;}
  setError('');onChange(uri);
 };
 const onFile=async e=>{
  const file=e.target.files?.[0];
  e.target.value='';
  if(!file)return;
  try{
   const uri=await fileToJpegDataUri(file);
   if(!avatarOk(uri)){setError('La imagen convertida a JPEG supera 85 KB. Usa una imagen más pequeña.');return;}
   setError('');onChange(uri);
  }catch{setError('No se pudo leer la imagen. Sube un archivo de imagen válido.');}
 };
 const preview=avatarOk(value);
 return <div className="sp-staff-avatar-field">
  <div className="sp-staff-avatar-preview">
   {preview?<img src={preview} alt="Avatar actual"/>:
    <span className="sp-person-avatar" aria-hidden="true">{name?.slice(0,1)?.toUpperCase()||'S'}</span>}
   <div><strong>Avatar de soporte</strong>
    <small className="muted">Se muestra junto a las respuestas en el chat. JPEG de 85 KB o menos; las imágenes subidas se convierten a JPEG automáticamente.</small></div>
  </div>
  <label>Subir imagen<input type="file" accept="image/*" disabled={busy} onChange={onFile}/></label>
  <label>Pegar data-URI JPEG<input type="text" value={paste} disabled={busy} placeholder="data:image/jpeg;base64,…"
   onChange={e=>setPaste(e.target.value)}/></label>
  <div className="sp-action-group">
   <button className="button" type="button" disabled={busy||!paste.trim()} onClick={()=>apply(paste.trim())}>Aplicar imagen pegada</button>
   {value&&<button className="button" type="button" disabled={busy} onClick={()=>{setError('');setPaste('');onChange(null);}}>Quitar avatar</button>}
  </div>
  {error&&<p className="form-message error" role="alert">{error}</p>}
 </div>;
}
function StaffRow({row,onSave,onReset,busy,roleLabels}){
 const [edit,setEdit]=useState({name:row.name,username:row.username,role:row.role,enabled:row.enabled,avatar:row.avatar??null});
 useEffect(()=>{setEdit({name:row.name,username:row.username,role:row.role,enabled:row.enabled,avatar:row.avatar??null});},[row.id,row.updatedAt]);
 return <article className="sp-personnel-row">
  {avatarOk(edit.avatar)?<img className="sp-person-avatar" src={avatarOk(edit.avatar)} alt=""/>:
   <div className="sp-person-avatar" aria-hidden="true">{row.name?.slice(0,1)?.toUpperCase()||'S'}</div>}
  <div className="sp-person-fields">
   <label>Nombre<input value={edit.name} maxLength={80} onChange={e=>setEdit(x=>({...x,name:e.target.value}))}/></label>
   <label>Usuario<input value={edit.username} maxLength={48} onChange={e=>setEdit(x=>({...x,username:e.target.value.toLowerCase()}))}/></label>
   <label>Cargo<select value={edit.role} onChange={e=>setEdit(x=>({...x,role:e.target.value}))}>
    {Object.entries(roleLabels).map(([v,name])=><option key={v} value={v}>{name}</option>)}</select></label>
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
  <AvatarField value={edit.avatar} name={edit.name} busy={busy} onChange={v=>setEdit(x=>({...x,avatar:v}))}/>
 </article>;
}
export default function StaffAdmin(){
 const router=useRouter(),[rows,setRows]=useState([]),[form,setForm]=useState(initial),
 [secret,setSecret]=useState(null),[busy,setBusy]=useState(false),
 [error,setError]=useState(''),[notice,setNotice]=useState(''),[access,setAccess]=useState(null),
 [customRoles,setCustomRoles]=useState([]),[roleDraft,setRoleDraft]=useState({
   code:'',name:'',permissions:['support.read']});
 const load=useCallback(async()=>{
  const [auth,staff]=await Promise.all([fetch('/api/admin/access',{cache:'no-store'}),
    fetch('/api/admin/staff',{cache:'no-store'})]);
  if(auth.status===401){router.replace('/admin/login');return;}
  if(!auth.ok||!staff.ok)throw Error('Acceso restringido a la gestión de personal.');
  const staffData=await staff.json();
  setAccess((await auth.json()).principal);setRows(staffData.staff||[]);
  setCustomRoles(staffData.roleDefinitions||[]);
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
 async function saveRole(body){
  setBusy(true);setError('');setNotice('');
  try{
   const r=await fetch('/api/admin/staff-roles',{method:'POST',cache:'no-store',
    credentials:'same-origin',headers:{'Content-Type':'application/json',
     'X-SPDecode-Admin-Action':'1'},body:JSON.stringify(body)});
   const data=await r.json();
   if(!r.ok)throw Error(data.error?.code||'No se pudo guardar el cargo.');
   setNotice('Cargo y permisos guardados. Las sesiones anteriores se invalidaron.');
   if(body.action==='create')setRoleDraft({code:'',name:'',permissions:['support.read']});
   await load();
  }catch(e){setError(e.message);}finally{setBusy(false);}
 }
 const roleLabels={...labels,...Object.fromEntries(customRoles.map(r=>[r.code,r.name]))};
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
     {Object.entries(roleLabels).map(([v,name])=><option value={v} key={v}>{name}</option>)}</select></label>
    <button className="button primary" type="submit" disabled={busy||!canName(form.name)}>Crear usuario y contraseña</button>
   </form>
  </section>}
  {access?.role==='owner'&&<section className="admin-card">
   <h2>Cargos personalizados</h2>
   <p className="muted">Configura exactamente qué puede consultar o responder el personal. Los cargos personalizados nunca reciben permisos de propietario ni acceso a secretos.</p>
   <form className="sp-staff-create" onSubmit={e=>{e.preventDefault();
    saveRole({action:'create',code:'x_'+roleDraft.code,name:roleDraft.name,
      permissions:roleDraft.permissions,enabled:true});}}>
    <label>Identificador del cargo<input required pattern="[a-z][a-z0-9_]{1,12}"
     maxLength={13} value={roleDraft.code}
     onChange={e=>setRoleDraft(x=>({...x,code:e.target.value.toLowerCase()}))}/></label>
    <label>Nombre visible<input required minLength={3} maxLength={72} value={roleDraft.name}
     onChange={e=>setRoleDraft(x=>({...x,name:e.target.value}))}/></label>
    <fieldset><legend>Permisos</legend>
     {['users.read','support.read','support.write','support.assign','billing.read'].map(p=>
      <label key={p}><input type="checkbox" checked={roleDraft.permissions.includes(p)}
       onChange={e=>setRoleDraft(x=>({...x,permissions:e.target.checked?
        [...x.permissions,p]:x.permissions.filter(v=>v!==p)}))}/>{p}</label>)}
    </fieldset>
    <button className="button primary" type="submit" disabled={busy}>
     Crear cargo</button>
   </form>
   <div className="sp-personnel-list">
    {customRoles.map(r=><CustomRoleRow key={r.code} row={r} busy={busy} onSave={saveRole}/>)}
   </div>
  </section>}
  <section className="admin-card"><h2>Personal autorizado</h2>
   <p className="muted">Al editar credenciales, estado o cargo se invalidan todas las sesiones anteriores.</p>
   {!rows.length?<p className="muted">No hay integrantes registrados.</p>:
    <div className="sp-personnel-list">{rows.map(row=><StaffRow key={row.id} row={row}
      busy={busy||access?.role!=='owner'}
      roleLabels={roleLabels}
      onSave={values=>mutate({action:'update',...values})} onReset={resetPassword}/>)}</div>}
  </section>
 </div>;
}