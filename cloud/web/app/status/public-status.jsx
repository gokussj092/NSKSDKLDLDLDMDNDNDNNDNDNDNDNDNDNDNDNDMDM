"use client";
import {useCallback,useEffect,useState} from "react";
export default function PublicStatus(){
  const [status,setStatus]=useState("loading");
  const [error,setError]=useState(false);
  const update=useCallback(async()=>{
    try {
      const result=await fetch("/api/site/status",{cache:"no-store"});
      if(!result.ok)throw Error("unavailable");
      const data=await result.json();
      setStatus(["not_ready","testing","maintenance"].includes(data.status)?data.status:"not_ready");
      setError(false);
    }catch{setStatus("not_ready");setError(true);}
  },[]);
  useEffect(()=>{update();},[update]);
  const label=status==="testing"?"Infraestructura en pruebas":
    status==="maintenance"?"Mantenimiento temporal":
    status==="loading"?"Comprobando estado":"Todavía no disponible públicamente";
  return <section className="status-panel" aria-live="polite">
    <span className="eyebrow"><span className="pulse"/> Estado público</span>
    <h2>{label}</h2><p>{error?"No fue posible obtener el estado.": "La publicación requiere pruebas finales, configuración y verificación de dispositivos."}</p>
    <button className="button subtle" type="button" onClick={update}>Actualizar estado</button>
  </section>;
}
