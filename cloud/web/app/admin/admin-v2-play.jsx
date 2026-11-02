"use client";
import {useEffect,useState} from "react";
const fields=["mode","deviceIntegrity","requireLicensed","requireSdk","minimumDeviceSdk",
 "requirePlayProtect","requireAccessRisk","requireAction","sessionSeconds"];
const flags=[["requireLicensed","Exigir licencia de Google Play"],
 ["requireSdk","Rechazar si Google no informa la versión Android"],
 ["requirePlayProtect","Exigir Play Protect sin incidencias"],
 ["requireAccessRisk","Rechazar riesgos de captura, control y superposición"],
 ["requireAction","Verificar Play Integrity también al descifrar"]];
export default function AdminV2Play({policy,runtime,busy,onSave}){
 const [draft,setDraft]=useState(null);
 useEffect(()=>{if(policy)setDraft(Object.fromEntries(fields.map(k=>[k,policy[k]])));},[policy?.revision]);
 if(!draft)return <p>Sin configuración Play disponible.</p>;
 const set=(key,value)=>setDraft(p=>({...p,[key]:value}));
 return <form className="sp-admin-device-policy" onSubmit={e=>{e.preventDefault();onSave(draft);}}>
  <h3>Google Play Integrity V2</h3>
  <p className="muted">Observación permanente por defecto: las señales de Google no impiden iniciar sesión.
   Exigirlas puede excluir APK externas, teléfonos antiguos, con root o con bootloader desbloqueado.
   La atestación criptográfica de hardware y la identidad de la aplicación siguen siendo obligatorias.</p>
  {runtime&&<p className="muted">{runtime.googleConfigured?"Cuenta de verificación Google configurada.":
   "Google no está configurado: sus señales aparecerán como desconocidas. El modo Exigir no estará disponible hasta completar la configuración."}
   {" RASP local: "+runtime.raspMode+". RASP de acceso: "+runtime.raspAccessMode+"."}</p>}
  <label htmlFor="v2-play-mode">Modo</label>
  <select id="v2-play-mode" value={draft.mode} disabled={busy} onChange={e=>set("mode",e.target.value)}>
   <option value="observe">Observar sin bloquear</option><option value="enforce">Exigir las comprobaciones seleccionadas</option>
   <option value="off">Desactivar consulta de Play</option>
  </select>
  <label htmlFor="v2-play-device">Integridad del dispositivo</label>
  <select id="v2-play-device" value={draft.deviceIntegrity} disabled={busy} onChange={e=>set("deviceIntegrity",e.target.value)}>
   <option value="observe">Solo observar</option><option value="basic">Básica</option>
   <option value="device">Dispositivo certificado</option><option value="strong">Fuerte (más restrictiva)</option>
  </select>
  <label htmlFor="v2-play-sdk">Android mínimo cuando Google informa el dato (SDK)</label>
  <input id="v2-play-sdk" type="number" min="24" max="100" required value={draft.minimumDeviceSdk}
   disabled={busy} onChange={e=>set("minimumDeviceSdk",Number(e.target.value))}/>
  {flags.map(([key,label])=><div className="sp-admin-switch-row" key={key}>
   <label htmlFor={"v2-play-"+key}>{label}</label>
   <input id={"v2-play-"+key} type="checkbox" checked={draft[key]} disabled={busy} onChange={e=>set(key,e.target.checked)}/>
  </div>)}
  <label htmlFor="v2-play-session">Reutilizar sesión (APK nueva)</label>
  <select id="v2-play-session" value={draft.sessionSeconds} disabled={busy} onChange={e=>set("sessionSeconds",Number(e.target.value))}>
   <option value={300}>5 minutos</option><option value={900}>15 minutos</option>
   <option value={1800}>30 minutos</option><option value={3600}>1 hora</option>
  </select>
  <p className="muted">Las comprobaciones seleccionadas bloquean únicamente en modo Exigir.
   Si falta un dato se muestra como desconocido. La verificación por operación consulta también a Google y aumenta la latencia.
   Guardar una política invalida las sesiones anteriores; la aplicación deberá autenticarse nuevamente.</p>
  <button className="button primary" type="submit" disabled={busy}>Guardar configuración Play</button>
 </form>;
}
