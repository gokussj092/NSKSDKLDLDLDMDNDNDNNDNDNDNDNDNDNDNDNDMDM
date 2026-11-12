"use client";
import Link from 'next/link';
import {useEffect,useMemo,useState} from 'react';
import PlanCarousel from './plan-carousel.jsx';
import {money} from './shop-common.jsx';

const SPEC={
 online:{
  includes:{es:['Uso gratuito sin crear una cuenta','Descifrado remoto de formatos habilitados','Catálogos VPN compatibles','Historial y exportación según funciones de la app'],en:['Free features without an account','Server decoding for enabled formats','Compatible VPN catalogs','History and export where supported']},
  excludes:{es:['No realiza el descifrado completamente sin conexión','No incluye una licencia Offline ni una API Key'],en:['Not a fully offline decoder','Does not include an Offline license or API key']}
 },
 'offline-3':{
  includes:{es:['Procesamiento local de los formatos compatibles','Uso sin conexión después de la activación','Hasta 3 dispositivos por licencia','Historial y resultados JSON locales','Sin anuncios en la versión Offline'],en:['Local processing for supported formats','Offline use after activation','Up to 3 devices per license','Local history and JSON results','No ads in Offline edition']},
  excludes:{es:['No incorpora los catálogos de Server VPN en la nube','No cubre formatos aún no integrados en Offline','La licencia temporal requiere una versión compatible de la APK'],en:['No cloud Server VPN catalogs','Formats not integrated Offline are unavailable','Timed licenses require a compatible APK version']}
 },
 'api-ip':{
  includes:{es:['API Key individual desde Mis productos','Una IP pública autorizada por clave','Respuestas estructuradas en JSON','Cuota de peticiones definida por el plan','Acceso durante el periodo contratado'],en:['Individual API key under My products','One authorized public IP per key','Structured JSON responses','Plan-based request quota','Access for the purchased duration']},
  excludes:{es:['No incluye una licencia Offline','No concede créditos de análisis avanzado','No hay llamadas ilimitadas'],en:['No Offline license included','No advanced-analysis credits included','No unlimited API usage']}
 },
 'analysis-credits':{
  includes:{es:['Paquetes de 1, 5, 10, 25, 50 y 100 créditos','Un crédito por análisis elegible completado','Saldo e historial en Mis créditos','Errores del servidor sin descuento definitivo','Descuentos por volumen según el paquete'],en:['Bundles of 1, 5, 10, 25, 50 and 100','One credit per eligible completed analysis','Balance and history under My credits','No final charge on server errors','Volume pricing on larger bundles']},
  excludes:{es:['No equivale a una licencia Offline','No garantiza compatibilidad con cualquier APK','La compra permanece cerrada hasta activar el consumo real'],en:['Not an Offline license','Not every APK is guaranteed compatible','Purchases remain disabled until actual usage is integrated']}
 }
};
const ORDER=['offline-3','api-ip','analysis-credits','online'];
export default function StoreExperience({products,currency,lang,t,onOpen}){
 const es=lang==='es';
 const [active,setActive]=useState('offline-3');
 const [selection,setSelection]=useState({'offline-3':'1m','api-ip':'1m','analysis-credits':'1c'});
 const [downloads,setDownloads]=useState({});
 useEffect(()=>{let mounted=true;Promise.all(['online','offline'].map(async key=>{
  try{const r=await fetch('/api/downloads/'+key+'?metadata',{cache:'no-store'});if(!r.ok)return [key,null];const d=await r.json();return [key,d.available?d:null];}catch{return [key,null];}
 })).then(rows=>{if(mounted)setDownloads(Object.fromEntries(rows));});return()=>{mounted=false;};},[]);
 const labels={'offline-3':t.offline,'api-ip':t.api,'analysis-credits':t.credits,online:t.online};
 const descriptions={'offline-3':t.offlineText,'api-ip':t.apiText,'analysis-credits':t.creditsText,online:t.onlineText};
 const selected=products.find(p=>p.id===active);
 const plans=selected?.plans||[];
 const current=plans.find(p=>p.id===selection[active])||plans.find(p=>p.id!=='base')||plans[0];
 const value=current?.prices?.[currency];
 const [unitPrice,unitLabel]=useMemo(()=>{
  if(!current||!value)return [null,null];
  if(active==='analysis-credits'&&current.credits)return [Math.round(value/current.credits),es?'por crédito':'per credit'];
  if(current.days&&current.id!=='base')return [Math.round(value/(current.days/30)),es?'por 30 días':'per 30 days'];
  return [null,null];
 },[active,current,currency,value,es]);
 const available=Boolean(selected?.available&&current?.available&&value);
 const choose=next=>setSelection(prev=>({...prev,[active]:next}));
 return <section className="sp-shop-experience" aria-label={es?'Productos y planes':'Products and plans'}>
  <div className="sp-shop-product-tabs" role="tablist" aria-label={es?'Productos':'Products'}>
   {ORDER.map(id=><button key={id} role="tab" id={'store-tab-'+id} type="button" aria-selected={active===id}
     aria-controls="store-product-detail" className={active===id?'active':''} onClick={()=>setActive(id)}>
     {labels[id]}<small>{id==='online'?t.free:id==='analysis-credits'?(es?'Paquetes':'Bundles'):id==='offline-3'?(es?'Hasta 3 dispositivos':'Up to 3 devices'):'API Key · IP'}</small>
   </button>)}
  </div>
  <div className="sp-shop-product-layout">
   <div id="store-product-detail" role="tabpanel" aria-labelledby={'store-tab-'+active} className="sp-shop-selected">
    <div className="sp-shop-selected-heading">
     <img src="/icon.svg" width="50" height="50" alt="SP-DECODE"/>
     <div><span className="sp-kicker">SP-DECODE</span><h2>{labels[active]}</h2><p>{descriptions[active]}</p></div>
    </div>
    {active==='online'?<div className="sp-shop-online-download"><strong>{t.free}</strong><p>{es?'La versión Online necesita conexión al servidor para descifrar. Puedes utilizar las funciones gratuitas sin iniciar sesión.':'Online uses a server connection to decode. You can use its free features without signing in.'}</p>
     {downloads.online?<a className="sp-shop-button" href="/api/downloads/online">{es?'Descargar APK Online':'Download Online APK'} · v{downloads.online.version}</a>:<p className="sp-shop-not-released">{es?'La APK Online aún no está publicada en este servidor.':'Online APK not published on this server yet.'}</p>}
    </div>:<>
     {selected?<PlanCarousel product={selected} currency={currency} lang={lang} selected={current?.id} onSelect={choose}/>:<div className="sp-loading">{es?'Cargando planes…':'Loading plans…'}</div>}
     {active==='offline-3'&&<div className="sp-shop-apk-link">{downloads.offline?<a href="/api/downloads/offline">{es?'Descargar APK Offline':'Download Offline APK'} · v{downloads.offline.version}</a>:<span>{es?'APK Offline pendiente de publicación verificada':'Offline APK awaiting verified release'}</span>}<small>{es?'La descarga no activa una licencia automáticamente.':'Downloading does not automatically activate a license.'}</small></div>}
    </>}
    <div className="sp-shop-inclusions">
     <div><h3><span className="sp-shop-include-icon">✓</span>{es?'Qué incluye':'Included'}</h3><ul>{SPEC[active].includes[lang].map(line=><li key={line}><span aria-hidden="true">✓</span>{line}</li>)}</ul></div>
     <div><h3><span className="sp-shop-exclude-icon">–</span>{es?'Qué no incluye':'Not included'}</h3><ul>{SPEC[active].excludes[lang].map(line=><li key={line}><span aria-hidden="true">–</span>{line}</li>)}</ul></div>
    </div>
   </div>
   <aside className="sp-shop-summary" aria-label={es?'Resumen del plan':'Plan summary'}>
    <span className="sp-kicker">{es?'RESUMEN':'SUMMARY'}</span><h3>{es?'Tu selección':'Your selection'}</h3>
    <dl>
     <div><dt>{es?'Producto':'Product'}</dt><dd>{labels[active]}</dd></div>
     <div><dt>{es?'Plan':'Plan'}</dt><dd>{active==='online'?t.free:current?.credits?current.credits+' '+(es?'créditos':'credits'):current?.days?current.days+' '+(es?'días':'days'):(es?'Pago único':'One-time')}</dd></div>
     {active==='offline-3'&&<div><dt>{es?'Dispositivos':'Devices'}</dt><dd>{es?'Hasta 3':'Up to 3'}</dd></div>}
     {active==='api-ip'&&<div><dt>API</dt><dd>{es?'1 IP autorizada':'1 authorized IP'}</dd></div>}
     {unitPrice&&<div><dt>{unitLabel}</dt><dd>{money(unitPrice,currency,lang)}</dd></div>}
     <div className="sp-shop-summary-total"><dt>{es?'Subtotal':'Subtotal'}</dt><dd>{active==='online'?t.free:value?money(value,currency,lang):'—'}</dd></div>
    </dl>
    <p className="sp-shop-summary-note">{es?'Los impuestos aplicables se calculan y muestran antes de confirmar el pago. No hay renovación automática.':'Applicable taxes are calculated and displayed before confirming payment. No automatic renewal.'}</p>
    {active==='online'?downloads.online?<a className="sp-shop-button" href="/api/downloads/online">{es?'Descargar APK gratuita':'Download free APK'}</a>:<Link className="sp-shop-button secondary" href="/#gallery">{t.explore}</Link>:
     <button type="button" className="sp-shop-button" disabled={!selected} onClick={()=>onOpen(selected,current?.id)}>
      {available?t.details:t.pending}
     </button>}
    <div className="sp-shop-summary-security"><span aria-hidden="true">◇</span>{es?'Las licencias y créditos solo se activan tras verificar el pago.':'Licenses and credits are activated only after payment verification.'}</div>
   </aside>
  </div>
 </section>;
}
