"use client";
import {useState} from "react";
import {useRouter} from "next/navigation";
export default function AdminLogin(){
  const [username,setUsername]=useState("");
  const [password,setPassword]=useState("");
  const [loading,setLoading]=useState(false);
  const [message,setMessage]=useState("");
  const router=useRouter();
  async function submit(event){
    event.preventDefault();if(loading)return;
    setLoading(true);setMessage("");
    try{
      const r=await fetch("/api/admin/login",{
        method:"POST",cache:"no-store",credentials:"same-origin",
        headers:{"Content-Type":"application/json","X-SPDecode-Admin-Action":"1"},
        body:JSON.stringify({username,password}),
      });
      const result=await r.json();
      setPassword("");
      if(!r.ok)throw Error(result.error?.code==="RATE_LIMITED"?"Demasiados intentos. Prueba más tarde.":"Acceso no autorizado o panel no configurado.");
      router.replace(result.staff?
        (result.mustChangePassword?"/admin/staff-password":
          result.role==="billing"?"/admin/users":"/admin/support"):"/admin");
      router.refresh();
    }catch(err){setMessage(err.message||"No se pudo iniciar sesión.");}
    finally{setLoading(false);}
  }
  return <form onSubmit={submit}>
    <label htmlFor="admin-username" className="field-label">Usuario</label>
    <input className="field" autoComplete="username" id="admin-username"
      type="text" required minLength={3} maxLength={64} value={username}
      onChange={e=>setUsername(e.target.value)} placeholder="Usuario de administración o personal"/>
    <label htmlFor="admin-password" className="field-label">Contraseña de acceso</label>
    <input className="field" autoComplete="current-password" id="admin-password"
      type="password" required minLength={16} maxLength={512} value={password}
      onChange={e=>setPassword(e.target.value)} placeholder="Contraseña de acceso"/>
    <button className="button primary" disabled={loading} type="submit">{loading?"Verificando…":"Acceder al panel"}</button>
    {message&&<p role="alert" className="form-message error">{message}</p>}
  </form>;
}
