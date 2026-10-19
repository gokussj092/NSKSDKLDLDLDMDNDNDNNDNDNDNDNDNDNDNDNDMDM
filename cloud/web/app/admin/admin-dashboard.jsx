"use client";
import {useCallback,useEffect,useState} from "react";
import {useRouter} from "next/navigation";
const requestOptions=(body)=>({
  method:"POST",cache:"no-store",credentials:"same-origin",
  headers:{"Content-Type":"application/json","X-SPDecode-Admin-Action":"1"},
  body:JSON.stringify(body),
});
const Indicator=({enabled})=><strong style={{color:enabled?"#8bf3c2":"#ffb2bc"}}>{enabled?"Disponible":"No disponible"}</strong>;
export default function AdminDashboard(){
  const [data,setData]=useState(null),[busy,setBusy]=useState(false);
  const [error,setError]=useState(""),[loading,setLoading]=useState(true);
  const router=useRouter();
  const refresh=useCallback(async()=>{
    try{
      const response=await fetch("/api/admin/session",{cache:"no-store",credentials:"same-origin"});
      if(response.status===401){router.replace("/admin/login");return;}
      if(!response.ok)throw Error("No se pudo consultar el estado administrativo.");
      const json=await response.json();setData(json);setError("");
    }catch(err){setError(err.message);}finally{setLoading(false);}
  },[router]);
  useEffect(()=>{refresh();},[refresh]);
  async function changeMaintenance(){
    if(!data||busy)return;
    const enable=!data.maintenance;
    if(!window.confirm(enable?"¿Activar mantenimiento y bloquear nuevas solicitudes de descifrado?":"¿Desactivar mantenimiento?"))return;
    setBusy(true);
    try{
      const r=await fetch("/api/admin/maintenance",requestOptions({enabled:enable}));
      if(!r.ok)throw Error("La operación fue rechazada.");
      await refresh();
    }catch(err){setError(err.message);}
    finally{setBusy(false);}
  }
  async function logout(){
    setBusy(true);
    try{
      const r=await fetch("/api/admin/logout",requestOptions({}));
      if(r.ok){router.replace("/admin/login");router.refresh();return;}
      throw Error("No se pudo cerrar la sesión.");
    }catch(err){setError(err.message);}
    finally{setBusy(false);}
  }
  if(loading)return <p aria-live="polite">Cargando estado del servidor…</p>;
  return <>
    {error&&<div className="form-message error" role="alert">{error}</div>}
    {data&&<div className="admin-grid">
      <section className="admin-card"><h2>Infraestructura</h2>
        <div className="admin-kv"><span>API configurada</span><Indicator enabled={data.services.apiConfigured}/></div>
        <div className="admin-kv"><span>Redis</span><Indicator enabled={data.services.redisConnected}/></div>
        <div className="admin-kv"><span>Worker privado</span><Indicator enabled={data.services.workerReady}/></div>
        <div className="admin-kv"><span>HTTP Injector Cloud</span><Indicator enabled={data.services.ehiImportConfigured}/></div>
        <div className="admin-kv"><span>Catálogo NUR</span><Indicator enabled={data.services.nurCatalogImportConfigured}/></div>
      </section>
      <section className="admin-card"><h2>Indicadores agregados · UTC</h2>
        <div className="admin-kv"><span>Descifrados correctos hoy</span><strong>{data.metrics.successfulDecodes}</strong></div>
        <div className="admin-kv"><span>Descifrados fallidos hoy</span><strong>{data.metrics.failedDecodes}</strong></div>
        <p className="muted">Los contadores no incluyen nombres de archivos, IPs, contraseñas ni resultados.</p>
      </section>
      <section className="admin-card" style={{gridColumn:"1/-1"}}>
        <h2>Modo mantenimiento</h2>
        <div className="admin-controls"><div>
          <strong>{data.maintenanceLocked?"Mantenimiento impuesto por despliegue":data.maintenance?"Mantenimiento activado":"Mantenimiento desactivado"}</strong>
          <p>Al activarlo, nuevas solicitudes de descifrado y sesiones se rechazarán. Las ya iniciadas pueden finalizar.</p>
          </div><button type="button" className={"button "+(data.maintenance?"primary":"danger")}
            onClick={changeMaintenance} disabled={busy||data.maintenanceLocked}>
              {data.maintenanceLocked?"Controlado desde el VPS":data.maintenance?"Reanudar nuevas solicitudes":"Activar mantenimiento"}
            </button>
        </div>
      </section>
    </div>}
    <div className="admin-actions">
      <button className="button subtle" type="button" onClick={refresh} disabled={busy}>Actualizar panel</button>
      <button className="button subtle" type="button" onClick={logout} disabled={busy}>Cerrar sesión</button>
    </div>
  </>;
}
