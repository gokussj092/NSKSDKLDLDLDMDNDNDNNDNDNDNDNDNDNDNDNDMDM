"use client";
import {useEffect,useState} from "react";
export default function AdminV1Protection(){
  const [policy,setPolicy]=useState(null),[busy,setBusy]=useState(false),[message,setMessage]=useState("");
  async function refresh(){
    try{
      const response=await fetch("/api/admin/v1-security",{credentials:"same-origin",cache:"no-store"});
      const data=await response.json();
      if(!response.ok)throw Error("No se pudo consultar la protección V1.");
      setPolicy(data.policy);setMessage("");
    }catch(error){setMessage(error.message);setPolicy(null);}
  }
  useEffect(()=>{refresh();},[]);
  async function toggle(){
    if(!policy||busy||policy.locked)return;
    const next=!policy.strict;
    const explanation=next?
      "Las APK anteriores, incluida 1.1.21, NO podrán abrir nuevas sesiones V1. Esta opción exige sesiones y pruebas V2 en operaciones V1 protegidas. ¿Continuar?":
      "Las APK anteriores podrán volver a utilizar la autenticación V1 habitual. ¿Desactivar el modo estricto?";
    if(!window.confirm(explanation))return;
    setBusy(true);setMessage("");
    try{
      const response=await fetch("/api/admin/v1-security",{
        method:"POST",credentials:"same-origin",cache:"no-store",
        headers:{"Content-Type":"application/json","X-SPDecode-Admin-Action":"1"},
        body:JSON.stringify({strict:next,confirmation:next?"ACTIVAR_V1_ESTRICTO":"DESACTIVAR_V1_ESTRICTO"})
      });
      const data=await response.json();
      if(!response.ok)throw Error(data.code==="V2_NOT_CONFIGURED"?
        "Primero configura completamente V2 y su verificador de hardware.":"Cambio rechazado ("+response.status+").");
      setPolicy(data.policy);
    }catch(error){setMessage(error.message);}finally{setBusy(false);}
  }
  return <section className="admin-card sp-admin-services">
    <div className="sp-admin-section-heading"><div>
      <h2>Protección de clientes V1</h2>
      <p className="muted">Control avanzado para la transición a sesiones vinculadas V2. No modifica la firma ni el código de las APK instaladas.</p>
    </div></div>
    <div className="sp-admin-switch-row">
      <div><strong>Exigir sesiones V2 para operaciones V1</strong>
        <small className="muted">{policy?.strict?
          "Modo estricto: los clientes antiguos sin pruebas V2 serán rechazados.":
          "Modo compatible: V1 conserva su autenticación y sus límites actuales."}</small>
        {policy?.locked&&<small className="sp-admin-status-note">Política bloqueada desde la configuración privada del VPS.</small>}
      </div>
      <button type="button" role="switch" className="sp-admin-switch" aria-label="Exigir sesiones V2 en V1"
        aria-checked={Boolean(policy?.strict)} disabled={!policy||busy||policy.locked} onClick={toggle}><span/></button>
    </div>
    <p className="muted">Antes de activar, verifica que las versiones nuevas funcionan con V2. Las rutas V1 públicas y las demás comprobaciones existentes no se convierten automáticamente en rutas V2. El estado se conserva al reiniciar el VPS.</p>
    {message&&<p role="status" className="form-message error">{message}</p>}
  </section>;
}
