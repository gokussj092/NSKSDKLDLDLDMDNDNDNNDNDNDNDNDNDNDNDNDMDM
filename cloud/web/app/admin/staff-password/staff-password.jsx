"use client";
import {useState} from 'react';
import {useRouter} from 'next/navigation';
export default function StaffPassword(){
 const router=useRouter(),[current,setCurrent]=useState(''),[next,setNext]=useState(''),
 [confirmation,setConfirmation]=useState(''),[error,setError]=useState(''),[busy,setBusy]=useState(false);
 async function submit(e){
  e.preventDefault();setBusy(true);setError('');
  try{
   const res=await fetch('/api/admin/staff-password',{method:'POST',credentials:'same-origin',
    headers:{'Content-Type':'application/json','X-SPDecode-Admin-Action':'1'},
    body:JSON.stringify({currentPassword:current,newPassword:next})});
   if(!res.ok)throw Error('Contraseña anterior incorrecta o credenciales no válidas.');
   router.replace('/admin/login');router.refresh();
  }catch(e){setError(e.message);}finally{setBusy(false);}
 }
 return <form className="admin-card sp-staff-password" onSubmit={submit}>
  <h2>Protege tu cuenta de personal</h2>
  <p>Debes cambiar la contraseña temporal antes de acceder al panel. La nueva contraseña debe contener al menos 16 caracteres.</p>
  <label>Contraseña temporal<input type="password" autoComplete="current-password" required value={current} onChange={e=>setCurrent(e.target.value)}/></label>
  <label>Nueva contraseña<input type="password" autoComplete="new-password" minLength={16} maxLength={128} required value={next} onChange={e=>setNext(e.target.value)}/></label>
  <label>Confirmar contraseña<input type="password" autoComplete="new-password" required value={confirmation} onChange={e=>setConfirmation(e.target.value)}/></label>
  {error&&<p role="alert" className="form-message error">{error}</p>}
  <button className="button primary" disabled={busy||next!==confirmation||next.length<16}>Guardar y volver a iniciar sesión</button>
 </form>;
}