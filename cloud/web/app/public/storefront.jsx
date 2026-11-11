"use client";
import Link from 'next/link';
import {useCallback,useEffect,useRef,useState} from 'react';
import {usePublicLocale} from './site-chrome.jsx';
import {shopFetch,money,errorMessage,ProductIcon} from './shop-common.jsx';
import StoreExperience from './store-experience.jsx';

const providers={
 stripe:{name:'Stripe',detail:{es:'Tarjetas y billeteras disponibles',en:'Cards and eligible wallets'},icon:'/brands/stripe.svg'},
 paypal:{name:'PayPal',detail:{es:'Cuenta PayPal',en:'PayPal account'},icon:'/brands/paypal.svg'},
 mercadopago:{name:'Mercado Pago',detail:{es:'Opciones de pago en México',en:'Payment options in Mexico'},icon:'/brands/mercadopago.svg'}
};
const countries='MX US CA GB ES DE FR IT PT NL BE CH AT IE AU NZ AR BR CL CO PE EC UY PY BO CR PA DO GT SV HN NI VE PR IN ID PH TH MY SG JP KR TW HK ZA NG KE EG MA AE SA TR PL CZ SE NO DK FI RO GR HU UA IL'.split(' ');
const copy={
 es:{tag:'TIENDA',title:'Elige lo que necesitas.',lead:'Licencias, acceso API y paquetes de créditos. Revisa cada plan, los impuestos aplicables y el total antes de pagar.',
 online:'SP-DECODE Online',free:'Gratis',onlineText:'Descarga y utiliza las funciones disponibles sin comprar una licencia.',explore:'Conocer la aplicación',
 offline:'SP-DECODE Offline',offlineText:'Licencias personales para usar tus configuraciones desde Android.',api:'SP-DECODE API',apiText:'Acceso para desarrolladores, con IP autorizada y cuota diaria.',
 credits:'Créditos de análisis',creditsText:'Paquetes para análisis avanzados elegibles; paga solo por trabajos completados.',
 plan:'Selecciona tu plan',details:'Revisar plan',pending:'Aún no disponible para comprar',currency:'Moneda',
 providers:'Métodos de pago',methods:'Solo estarán disponibles los proveedores configurados y compatibles con tu moneda y país.',providerPending:'En configuración',providerReady:'Configurado',
 info:'Compras verificadas',infoText:'Los accesos y créditos se entregan únicamente después de la confirmación del proveedor.',
 checkout:'Revisa tu compra',checkoutLead:'Selecciona el método de pago. Verifica las condiciones y el importe total.',close:'Cerrar',country:'País de facturación',region:'Estado / región',ip:'IP pública del servidor',login:'Inicia sesión con Google para adquirir este producto.',signIn:'Iniciar sesión',quote:'Calcular total',continue:'Continuar al pago',
 subtotal:'Subtotal',tax:'Impuestos',total:'Total',accept:'Acepto los términos de compra y la política de privacidad.',reviewTerms:'Leer términos',
 unavailable:'Este plan estará disponible después de configurar el producto, su pasarela y la entrega.',test:'Modo de pruebas: no se realizan cobros reales.',live:'La compra está sujeta a condiciones e impuestos del destino.',
 faq:'Antes de comprar',faqItems:[['¿La app Online es gratuita?','Sí. La aplicación Online mantiene sus funciones gratuitas.'],['¿Qué significa un crédito?','Un crédito equivale a un análisis avanzado elegible completado correctamente. Los errores atribuibles al servidor no se cobran.'],['¿Cómo se calculan los descuentos?','El ahorro mostrado se compara con el precio de referencia por unidad o por mes configurado.'],['¿Puedo comprar ya?','La venta se habilita por producto después de verificar la entrega y configurar los métodos de pago.']]},
 en:{tag:'STORE',title:'Choose what you need.',lead:'Licenses, API access and analysis credit bundles. Review each plan, applicable taxes and total before paying.',
 online:'SP-DECODE Online',free:'Free',onlineText:'Download and use available features without purchasing a license.',explore:'Explore the app',
 offline:'SP-DECODE Offline',offlineText:'Personal licenses for Android configuration management.',api:'SP-DECODE API',apiText:'Developer access bound to an authorized IP and daily quota.',
 credits:'Analysis credits',creditsText:'Packs for eligible advanced analyses; pay only for completed jobs.',
 plan:'Choose your plan',details:'Review plan',pending:'Not yet available for purchase',currency:'Currency',
 providers:'Payment methods',methods:'Only configured providers supported for your country and currency will be available.',providerPending:'Setting up',providerReady:'Configured',
 info:'Verified purchases',infoText:'Access and credits are delivered only after payment confirmation from the provider.',
 checkout:'Review purchase',checkoutLead:'Choose a payment method. Review terms and the final total.',close:'Close',country:'Billing country',region:'State / region',ip:'Server public IP',login:'Sign in with Google to purchase this item.',signIn:'Sign in',quote:'Calculate total',continue:'Continue to checkout',
 subtotal:'Subtotal',tax:'Tax',total:'Total',accept:'I accept the purchase terms and privacy policy.',reviewTerms:'Read terms',
 unavailable:'This plan will be available once the product, provider and delivery are configured.',test:'Test mode: no real charges.',live:'Purchases are subject to the applicable terms and taxes.',
 faq:'Before you buy',faqItems:[['Is Online free?','Yes. The Online application continues to offer its free features.'],['What is one credit?','One credit equals one successfully completed eligible advanced analysis. Server errors are not charged.'],['How do discounts work?','Displayed savings compare against the configured per-unit or monthly price.'],['Can I buy now?','Each product becomes purchasable once fulfillment is verified and payment methods are configured.']]}
};
function PaymentMark({id,lang,details=true}){const p=providers[id];return <span className="sp-pay-mark"><span className="sp-pay-icon"><img src={p.icon} alt="" width="24" height="24"/></span><span><strong>{p.name}</strong>{details&&<small>{p.detail[lang]}</small>}</span></span>;}
export default function Storefront(){
 const {lang}=usePublicLocale(),t=copy[lang];
 const [catalog,setCatalog]=useState(null),[account,setAccount]=useState(null),[error,setError]=useState('');
 const [currency,setCurrency]=useState('USD'),[selected,setSelected]=useState(null),[term,setTerm]=useState('1m');
 const [provider,setProvider]=useState('stripe'),[country,setCountry]=useState('MX'),[region,setRegion]=useState(''),[ip,setIp]=useState('');
 const [accepted,setAccepted]=useState(false),[quote,setQuote]=useState(null),[busy,setBusy]=useState(false);
 const dialog=useRef(null),idempotency=useRef(null);
 useEffect(()=>{let alive=true;Promise.all([shopFetch('/api/store/catalog'),shopFetch('/api/account')]).then(([a,b])=>{if(alive){setCatalog(a);setAccount(b);setError('');}}).catch(e=>{if(alive)setError(errorMessage(e.message,lang));});return()=>{alive=false;};},[lang]);
 useEffect(()=>{setQuote(null);idempotency.current=null;},[currency,provider,country,region,ip,selected,term]);
 function open(product,chosen){setSelected(product);setTerm(chosen||product.plans?.[0]?.id||'base');setQuote(null);setError('');setAccepted(false);setProvider(product.providers?.find(x=>x!=='mercadopago'||currency==='MXN')||'stripe');dialog.current?.showModal();}
 async function review(){setBusy(true);setError('');try{setQuote(await shopFetch('/api/store/quote',{product:selected.id,term,provider,currency,country,region}));}catch(e){setError(errorMessage(e.message,lang));}finally{setBusy(false);}}
 async function pay(){setBusy(true);setError('');try{idempotency.current??=crypto.randomUUID();const out=await shopFetch('/api/store/checkout',{product:selected.id,term,provider,currency,country,region,allowedIp:ip,version:quote.version,idempotencyKey:idempotency.current,acceptedTerms:'2026-11-10'});window.location.assign(out.url||'/orders?order='+out.orderId);}catch(e){setError(errorMessage(e.message,lang));setBusy(false);}}
 const products=catalog?.products||[],current=selected?.plans?.find(p=>p.id===term),amount=current?.prices?.[currency];
 const available=Boolean(selected?.available&&current?.available&&amount&&selected?.providers?.some(p=>p===provider)&&!(provider==='mercadopago'&&currency!=='MXN'));
 const names=new Intl.DisplayNames([lang],{type:'region'});
 return <main id="main" className="sp-shop sp-amoled-shop">
  <header className="sp-container sp-amoled-shop-hero"><div><span className="sp-kicker">{t.tag}</span><h1>{t.title}</h1><p>{t.lead}</p></div><label>{t.currency}<select value={currency} onChange={e=>setCurrency(e.target.value)}><option>USD</option><option>MXN</option><option>EUR</option></select></label></header>
  {error&&!selected&&<p className="sp-container sp-form-error" role="alert">{error}</p>}
  {catalog&&!catalog.live&&catalog.products.some(p=>p.available)&&<p className="sp-container sp-soft-notice">{t.test}</p>}
  <div className="sp-container"><StoreExperience products={catalog?.products||[]} currency={currency} lang={lang} t={t} onOpen={open}/></div>
  <section className="sp-container sp-amoled-payment-info"><div><span className="sp-kicker">CHECKOUT</span><h2>{t.providers}</h2><p>{t.methods}</p></div><div className="sp-payment-logo-grid">{Object.entries(providers).map(([id,p])=><div className="sp-payment-logo-card" key={id}><PaymentMark id={id} lang={lang}/><small>{products.some(x=>x.providers?.includes(id))?t.providerReady:t.providerPending}</small></div>)}</div></section>
  <section className="sp-container sp-shop-assurances"><article><h3>{t.info}</h3><p>{t.infoText}</p></article><article><h3>{t.faq}</h3>{t.faqItems.map(([q,a])=><details key={q} className="sp-shop-minifaq"><summary>{q}</summary><p>{a}</p></details>)}</article></section>
  <dialog ref={dialog} className="sp-checkout sp-premium-checkout" aria-labelledby="sp-checkout-title" onClose={()=>{setSelected(null);setError('');}}>
   <div className="sp-checkout-head"><span className="sp-kicker">SP-DECODE · CHECKOUT</span><button type="button" className="sp-dialog-close" aria-label={t.close} onClick={()=>dialog.current?.close()}>×</button></div>
   {selected&&<><h2 id="sp-checkout-title">{selected.id==='analysis-credits'?t.credits:selected.id==='offline-3'?t.offline:t.api}</h2><p>{t.checkoutLead}</p>
    <div className="sp-checkout-product-preview"><img src="/icon.svg" alt="" width="45" height="45"/><div><strong>{current?.credits?current.credits+' '+(lang==='es'?'créditos':'credits'):current?.days?current.days+' '+(lang==='es'?'días':'days'):lang==='es'?'Pago único':'One-time'}</strong><small>{selected.id==='analysis-credits'?t.credits:selected.id==='offline-3'?t.offline:t.api}</small></div><strong>{amount?money(amount,currency,lang):'—'}</strong></div>
    {!available?<div className="sp-soft-notice">{t.unavailable}</div>:!account?.user?<div className="sp-checkout-signin"><p>{t.login}</p><Link className="sp-shop-button" href="/login?next=/store">{t.signIn}</Link></div>:<>
     <div className="sp-checkout-methods">{selected.providers.filter(id=>id!=='mercadopago'||currency==='MXN').map(id=><label key={id} className={'sp-checkout-method sp-premium-method '+(provider===id?'chosen':'')}><input type="radio" name="provider" checked={provider===id} onChange={()=>setProvider(id)}/><PaymentMark id={id} lang={lang}/></label>)}</div>
     <div className="sp-form-grid"><label>{t.country}<select value={country} onChange={e=>setCountry(e.target.value)}>{countries.map(code=><option value={code} key={code}>{names.of(code)}</option>)}</select></label><label>{t.region}<input type="text" autoComplete="address-level1" maxLength={12} value={region} onChange={e=>setRegion(e.target.value.toUpperCase())}/></label></div>
     {selected.id==='api-ip'&&<label>{t.ip}<input type="text" placeholder="IPv4 / IPv6" value={ip} autoComplete="off" spellCheck="false" onChange={e=>setIp(e.target.value.trim())}/></label>}
     {!quote?<button type="button" className="sp-shop-button" disabled={busy} onClick={review}>{busy?'…':t.quote}</button>:<>
       <dl className="sp-order-total"><div><dt>{t.subtotal}</dt><dd>{money(quote.subtotal,currency,lang)}</dd></div><div><dt>{quote.taxLabel||t.tax}</dt><dd>{money(quote.tax,currency,lang)}</dd></div><div className="total"><dt>{t.total}</dt><dd>{money(quote.total,currency,lang)}</dd></div></dl>
       <label className="sp-consent"><input type="checkbox" checked={accepted} onChange={e=>setAccepted(e.target.checked)}/><span>{t.accept} <Link href="/terms" target="_blank">{t.reviewTerms}</Link></span></label><button type="button" className="sp-shop-button" disabled={busy||!accepted} onClick={pay}>{busy?'…':t.continue}</button>
     </>}
    </>}
    {error&&<p className="sp-form-error" role="alert">{error}</p>}
   </>}
  </dialog>
 </main>;
}
