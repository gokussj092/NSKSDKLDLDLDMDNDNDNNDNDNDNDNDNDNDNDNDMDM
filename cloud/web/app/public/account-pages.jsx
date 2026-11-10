"use client";
import Link from 'next/link';
import {useCallback,useEffect,useState} from 'react';
import {usePublicLocale,usePublicSession} from './site-chrome.jsx';
import {shopFetch,authClient,money,errorMessage,ProductIcon} from './shop-common.jsx';

const statuses={es:{created:'Preparando pago',pending:'Pago pendiente',paid:'Pago confirmado',refunded:'Reembolsado',disputed:'En revisión',failed:'No completado'},en:{created:'Preparing payment',pending:'Payment pending',paid:'Paid',refunded:'Refunded',disputed:'Under review',failed:'Not completed'}};
function useSnapshot(){
 const [data,setData]=useState(null),[error,setError]=useState('');
 const refresh=useCallback(async()=>{try{const next=await shopFetch('/api/account');setData(next);setError('');return next;}catch(e){setError(e.message||'SERVICE_UNAVAILABLE');throw e;}},[]);
 useEffect(()=>{refresh().catch(()=>{});},[refresh]);
 return {data,error,refresh};
}
function PrivatePage({title,subheading,path,children}){
 const {lang}=usePublicLocale(),{data,error,refresh}=useSnapshot(),es=lang==='es';
 return <main id="main" className="sp-public-main sp-private-page sp-container">
  <header className="sp-private-heading"><span className="sp-kicker">SP-DECODE · {es?'MI ESPACIO':'MY SPACE'}</span><h1>{title[lang]}</h1><p>{subheading[lang]}</p></header>
  {error&&<div role="alert" className="sp-form-error">{errorMessage(error,lang)} <button type="button" className="sp-text-button" onClick={()=>refresh().catch(()=>{})}>{es?'Reintentar':'Retry'}</button></div>}
  {!data?<div className="sp-loading" role="status">{es?'Cargando tu información…':'Loading your account…'}</div>:!data.user?<div className="sp-private-gate"><div className="sp-private-gate-icon"><img src="/icon.svg" alt="" width="58" height="58"/></div><h2>{es?'Tu espacio comienza aquí':'Your space starts here'}</h2><p>{es?'Inicia sesión con Google para consultar tu información. La tienda y las funciones públicas siguen disponibles sin cuenta.':'Sign in with Google to access your information. The store and public features are available without an account.'}</p><Link className="sp-shop-button" href={'/login?next='+encodeURIComponent(path)}>{es?'Continuar con Google':'Continue with Google'}</Link><Link className="sp-private-gate-store" href="/store">{es?'Explorar tienda':'Explore store'}</Link></div>:children(data,refresh)}
 </main>;
}
function ProfileContent({data,refresh}){
 const {lang}=usePublicLocale(),{refreshAccount}=usePublicSession(),es=lang==='es';
 const [name,setName]=useState(data.user.name||''),[username,setUsername]=useState(data.user.username||''),[bio,setBio]=useState(data.user.bio||'');
 const [avatar,setAvatar]=useState(undefined),[saving,setSaving]=useState(false),[message,setMessage]=useState(''),[error,setError]=useState(''),[removing,setRemoving]=useState(false);
 const photo=avatar===null?data.user.googleAvatar:avatar||data.user.avatar;
 async function choosePhoto(event){
  const file=event.target.files?.[0];event.target.value='';if(!file)return;
  if(!['image/png','image/jpeg','image/webp'].includes(file.type)||file.size>4*1024*1024){setError(es?'Elige PNG, JPG o WebP de máximo 4 MB.':'Use a PNG, JPG or WebP under 4 MB.');return;}
  try{
   const object=URL.createObjectURL(file);const image=new Image();
   await new Promise((resolve,reject)=>{image.onload=resolve;image.onerror=reject;image.src=object;});
   URL.revokeObjectURL(object);
   const canvas=document.createElement('canvas'),max=256,scale=Math.min(1,max/Math.max(image.width,image.height));
   canvas.width=Math.round(image.width*scale);canvas.height=Math.round(image.height*scale);
   const ctx=canvas.getContext('2d');if(!ctx)throw Error('CANVAS');
   ctx.drawImage(image,0,0,canvas.width,canvas.height);
   const encoded=canvas.toDataURL('image/jpeg',0.82);
   if(encoded.length>110000)throw Error('TOO_LARGE');
   setAvatar(encoded);setError('');
  }catch{setError(es?'No pudimos procesar la imagen. Prueba con otra foto.':'Could not process the image. Try another photo.');}
 }
 async function save(e){e.preventDefault();setSaving(true);setError('');setMessage('');
  try{await shopFetch('/api/account/profile',{name,username,bio,...(avatar===undefined?{}:{avatarData:avatar})},'PATCH');await refresh();await refreshAccount();setAvatar(undefined);setMessage(es?'Perfil actualizado.':'Profile updated.');}
  catch(e){setError(errorMessage(e.message,lang));}finally{setSaving(false);}
 }
 async function deleteAccount(){
  setSaving(true);setError('');try{const result=await authClient.deleteUser({callbackURL:'/'});if(result.error)throw Error(result.error.code);window.location.assign('/');}
  catch(e){setError(errorMessage(e.message,lang));setSaving(false);}
 }
 return <div className="sp-profile-stack">
  <section className="sp-profile-card"><div className="sp-profile-cover"><span>SP-DECODE</span><small>{es?'PERFIL PERSONAL':'PERSONAL PROFILE'}</small></div><div className="sp-profile-card-body"><div className="sp-photo-row"><div className="sp-profile-photo">{photo?<img src={photo} alt={es?'Foto de perfil':'Profile picture'} referrerPolicy="no-referrer"/>:<span>{name.slice(0,1).toUpperCase()}</span>}</div><div><label className="sp-photo-upload" htmlFor="sp-photo-file">{es?'Cambiar foto':'Change photo'}</label><input id="sp-photo-file" type="file" accept="image/jpeg,image/png,image/webp" onChange={choosePhoto} className="sp-visually-hidden"/>{(data.user.avatar||avatar)&&<button type="button" className="sp-text-button" onClick={()=>setAvatar(null)}>{es?'Usar foto de Google':'Use Google photo'}</button>}<small>{es?'Imagen optimizada para tu perfil.':'Optimized profile image.'}</small></div></div>
   <form onSubmit={save}><div className="sp-form-grid"><label>{es?'Nombre visible':'Display name'}<input type="text" required minLength="1" maxLength="80" value={name} onChange={e=>setName(e.target.value)} autoComplete="name"/></label><label>{es?'Usuario único':'Unique username'}<div className="sp-handle-input"><span>@</span><input required minLength="3" maxLength="24" pattern="[A-Za-z][A-Za-z0-9_]{2,23}" value={username} onChange={e=>setUsername(e.target.value)} autoComplete="username" spellCheck="false"/></div></label></div>
    <label>{es?'Biografía':'Bio'}<textarea rows="3" maxLength="180" value={bio} onChange={e=>setBio(e.target.value)} placeholder={es?'Cuéntanos algo sobre ti (opcional)':'Tell us a little about yourself (optional)'}/><small>{bio.length}/180</small></label>
    <label>{es?'Correo conectado':'Connected email'}<input value={data.user.email} readOnly/><small>{es?'Se administra desde tu cuenta de Google.':'Managed through your Google account.'}</small></label>
    {error&&<p className="sp-form-error" role="alert">{error}</p>}{message&&<p className="sp-form-success" role="status">{message}</p>}
    <button className="sp-shop-button" disabled={saving}>{saving?'…':es?'Guardar perfil':'Save profile'}</button>
   </form></div></section>
   <section className="sp-profile-shortcuts"><h2>{es?'Accesos rápidos':'Quick links'}</h2><div><Link href="/orders">{es?'Mis compras':'My purchases'}<span>→</span></Link><Link href="/receipts">{es?'Mis recibos':'My receipts'}<span>→</span></Link><Link href="/products">{es?'Mis productos':'My products'}<span>→</span></Link></div></section>
   <section className="sp-profile-danger"><h2>{es?'Privacidad y cuenta':'Privacy and account'}</h2><p>{es?'Puedes solicitar la eliminación de tu cuenta. Se revocarán tus accesos activos y se conservarán únicamente los registros exigidos por obligaciones legales.':'You can request account deletion. Active access will be revoked and only legally required records retained.'}</p><div><Link href="/privacy">{es?'Ver privacidad':'Privacy policy'}</Link><button className="sp-text-button danger" onClick={()=>setRemoving(!removing)}>{es?'Eliminar cuenta':'Delete account'}</button></div>
    {removing&&<div className="sp-delete-confirm"><strong>{es?'¿Eliminar permanentemente tu cuenta?':'Permanently delete your account?'}</strong><p>{es?'La acción no se puede deshacer.':'This cannot be undone.'}</p><button type="button" disabled={saving} className="sp-shop-button danger" onClick={deleteAccount}>{es?'Sí, eliminar cuenta':'Yes, delete account'}</button><button type="button" className="sp-text-button" onClick={()=>setRemoving(false)}>{es?'Cancelar':'Cancel'}</button></div>}
   </section>
 </div>;
}
export function ProfilePage(){
 return <PrivatePage path="/account" title={{es:'Tu perfil',en:'Your profile'}} subheading={{es:'Tu identidad en SP-DECODE, a tu manera.',en:'Your identity on SP-DECODE, your way.'}}>{(data,refresh)=><ProfileContent data={data} refresh={refresh}/>}</PrivatePage>;
}
export function OrdersPage(){
 const {lang}=usePublicLocale(),es=lang==='es';
 return <PrivatePage path="/orders" title={{es:'Mis compras',en:'My purchases'}} subheading={{es:'Consulta todos tus pedidos y su estado.',en:'Track all your orders and payment status.'}}>{(data)=><div className="sp-record-list">{!data.orders?.length?<div className="sp-empty-state">{es?'Aún no tienes compras.':'You have no orders yet.'} <Link href="/store">{es?'Visitar tienda':'Visit store'}</Link></div>:data.orders.map(order=><article className="sp-record-card" key={order.id}><div className="sp-record-symbol"><ProductIcon type={order.product_id}/></div><div className="sp-record-details"><h2>{order.product_id==='offline-3'?'SP-DECODE Offline':'SP-DECODE API'}</h2><small>{new Date(order.created_at).toLocaleDateString(lang==='es'?'es-MX':'en-US',{dateStyle:'medium'})}</small><span className="sp-record-id">{es?'Pedido':'Order'} {order.id.slice(0,8)}</span></div><div className="sp-record-meta"><strong>{money(order.quote.total,order.quote.currency,lang)}</strong><span className={'sp-status '+order.status}>{statuses[lang][order.status]||order.status}</span>{order.status==='paid'&&<Link href="/receipts">{es?'Ver recibo':'View receipt'}</Link>}</div></article>)}</div>}</PrivatePage>;
}
export function ReceiptsPage(){
 const {lang}=usePublicLocale(),es=lang==='es';
 return <PrivatePage path="/receipts" title={{es:'Mis recibos',en:'My receipts'}} subheading={{es:'Comprobantes comerciales de tus pagos confirmados.',en:'Commercial receipts for confirmed payments.'}}>{(data)=><div className="sp-record-list">{!data.orders?.some(x=>x.status==='paid'||x.status==='refunded')?<div className="sp-empty-state">{es?'Tus recibos aparecerán aquí cuando se confirme una compra.':'Your receipts will appear here after a payment is confirmed.'}</div>:data.orders.filter(o=>['paid','refunded'].includes(o.status)).map(o=><article key={o.id} className="sp-receipt-card"><div className="sp-card-heading"><h2>{o.product_id==='offline-3'?'SP-DECODE Offline':'SP-DECODE API'}</h2><span className={'sp-status '+o.status}>{statuses[lang][o.status]}</span></div><dl><div><dt>{es?'Referencia':'Reference'}</dt><dd>{o.id}</dd></div><div><dt>{es?'Fecha':'Date'}</dt><dd>{new Date(o.created_at).toLocaleDateString(lang==='es'?'es-MX':'en-US')}</dd></div><div><dt>{es?'Subtotal':'Subtotal'}</dt><dd>{money(o.quote.subtotal,o.quote.currency,lang)}</dd></div><div><dt>{o.quote.taxLabel||'Tax'}</dt><dd>{money(o.quote.tax,o.quote.currency,lang)}</dd></div><div className="sp-receipt-total"><dt>{es?'Total':'Total'}</dt><dd>{money(o.quote.total,o.quote.currency,lang)}</dd></div></dl><small>{es?'Comprobante comercial; no sustituye una factura fiscal.':'Commercial receipt; not a tax invoice.'}</small><Link href="/support">{es?'Solicitar ayuda':'Get support'}</Link></article>)}</div>}</PrivatePage>;
}
export function ProductsPage(){
 const {lang}=usePublicLocale(),es=lang==='es', [secret,setSecret]=useState(null),[busy,setBusy]=useState(false),[err,setErr]=useState('');
 async function reveal(item,refresh,rotate=false){
  if(!window.confirm(rotate?(es?'Se invalidará tu API Key anterior. ¿Continuar?':'Your previous API key will be revoked. Continue?'):(es?'Esta clave solo se muestra una vez. ¿Listo para guardarla?':'This key is shown once. Ready to save it?')))return;
  setBusy(true);setErr('');try{const s=await shopFetch('/api/store/claim',{id:item.id,rotate});setSecret(s);await refresh();}catch(e){setErr(errorMessage(e.message,lang));}finally{setBusy(false);}
 }
 return <PrivatePage path="/products" title={{es:'Mis productos',en:'My products'}} subheading={{es:'Consulta tus licencias y administra tus accesos.',en:'View your licenses and manage access.'}}>{(data,refresh)=><div className="sp-record-list">{err&&<p role="alert" className="sp-form-error">{err}</p>}{secret&&<div className="sp-secret" role="status"><strong>{es?'Guarda tu clave. No volverá a mostrarse.':'Save your key. It will not be shown again.'}</strong><code>{secret.token}</code><button className="sp-shop-button" onClick={()=>navigator.clipboard.writeText(secret.token)}>{es?'Copiar clave':'Copy key'}</button><button className="sp-text-button" onClick={()=>setSecret(null)}>{es?'Ya la guardé':'I saved it'}</button></div>}{!data.entitlements?.length?<div className="sp-empty-state">{es?'No tienes productos activos todavía.':'You do not have any products yet.'} <Link href="/store">{es?'Explorar tienda':'Explore store'}</Link></div>:data.entitlements.map(item=><article className="sp-record-card sp-product-record" key={item.id}><div className="sp-record-symbol"><ProductIcon type={item.product_id}/></div><div className="sp-record-details"><h2>{item.product_id==='offline-3'?'SP-DECODE Offline':'SP-DECODE API'}</h2><small>{item.product_id==='offline-3'?(es?'Licencia personal · 3 dispositivos':'Personal license · 3 devices'):(item.allowed_ip||'—')+' · '+item.quota+' '+(es?'operaciones/día':'requests/day')}</small>{item.expires_at&&<small>{es?'Vence':'Expires'}: {new Date(item.expires_at).toLocaleDateString(lang==='es'?'es-MX':'en-US')}</small>}{!item.payment_live&&<small>{es?'Entorno de prueba':'Test environment'}</small>}</div><div className="sp-record-meta"><span className={'sp-status '+item.status}>{item.status==='active'?(es?'Activo':'Active'):(es?'Revocado':'Revoked')}</span>{item.status==='active'&&item.payment_live===data.live&&(!item.claimed_at?<button type="button" disabled={busy} className="sp-shop-button" onClick={()=>reveal(item,refresh)}>{es?'Mostrar clave':'Reveal key'}</button>:<><small>{item.token_prefix}…</small>{item.product_id==='api-ip'&&<button type="button" disabled={busy} className="sp-text-button" onClick={()=>reveal(item,refresh,true)}>{es?'Rotar clave':'Rotate key'}</button>}</>)}</div></article>)}</div>}</PrivatePage>;
}
