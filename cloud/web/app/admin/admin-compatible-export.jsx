'use client';
import {useEffect,useState} from 'react';
export default function AdminCompatibleExport(){
 const [policy,setPolicy]=useState(null),[minimum,setMinimum]=useState('1.1.21');
 const [busy,setBusy]=useState(false),[error,setError]=useState('');
 async function load(){
  try{const r=await fetch('/api/admin/compatible-exports',{cache:'no-store',credentials:'same-origin'});
   if(!r.ok)throw Error('No se pudo consultar la política de exportación.');
   const p=(await r.json()).compatibleExports;setPolicy(p);setMinimum(p.minimumAppVersion);setError('');
  }catch(e){setError(e.message);}
 }
 useEffect(()=>{load();},[]);
 async function save(enabled){
  if(!policy||busy||policy.locked)return;
  setBusy(true);setError('');
  try{
   const r=await fetch('/api/admin/compatible-exports',{method:'POST',cache:'no-store',credentials:'same-origin',
    headers:{'Content-Type':'application/json','X-SPDecode-Admin-Action':'1'},
    body:JSON.stringify({enabled,minimumAppVersion:minimum,expectedRevision:policy.revision})});
   if(!r.ok)throw Error(r.status===409?'La política cambió o está bloqueada. Actualiza el panel.':'No se pudo guardar la política. La versión mínima admitida es 1.1.21.');
   setPolicy((await r.json()).compatibleExports);
  }catch(e){setError(e.message);}finally{setBusy(false);}
 }
 return <section className='admin-card sp-admin-services'>
  <h2>Exportación para aplicaciones VPN</h2>
  <p className='muted'>Activa la integración de archivos compatibles para versiones admitidas. Los clientes anteriores conservan su catálogo habitual. Las notificaciones del teléfono se implementarán por separado.</p>
  {error&&<p role='alert' className='form-message error'>{error}</p>}
  <div className='sp-admin-switch-row'><div><strong>Exportación compatible</strong>
   <small className='muted'>{policy?.locked?'Bloqueada por configuración del VPS':policy?.enabled?'Activa para las versiones admitidas':'Desactivada'}</small></div>
   <button role='switch' className='sp-admin-switch' aria-label='Exportación compatible' aria-checked={policy?.enabled??false}
    disabled={!policy||busy||policy.locked} onClick={()=>save(!policy.enabled)}><span/></button></div>
  <label>Versión mínima de SP-DECODE<input aria-label='Versión mínima para exportación' value={minimum} maxLength={14}
   onChange={e=>setMinimum(e.target.value)} disabled={busy||policy?.locked} placeholder='1.1.21'/></label>
  <button type='button' className='button secondary' onClick={()=>save(policy.enabled)} disabled={!policy||busy||policy.locked}>Guardar versión mínima</button>
  <p className='muted'>La API comprueba versión y protocolo en cada solicitud. El cambio queda guardado en el volumen de configuración; no publica una APK ni altera las configuraciones que el usuario ya guardó.</p>
 </section>;
}
