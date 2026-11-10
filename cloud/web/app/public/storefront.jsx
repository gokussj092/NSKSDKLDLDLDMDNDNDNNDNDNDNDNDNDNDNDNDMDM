"use client";
import Link from 'next/link';
import {useEffect,useRef,useState} from 'react';
import {usePublicLocale} from './site-chrome.jsx';
import {shopFetch,money,errorMessage,ProductIcon} from './shop-common.jsx';

const providers={
 stripe:{name:'Stripe',detail:{es:'Tarjetas y wallets elegibles',en:'Cards and eligible wallets'},asset:'/brands/stripe.svg'},
 paypal:{name:'PayPal',detail:{es:'PayPal y métodos admitidos',en:'PayPal and supported methods'},asset:'/brands/paypal.svg'},
 mercadopago:{name:'Mercado Pago',detail:{es:'México · métodos locales',en:'Mexico · local methods'},asset:'/brands/mercadopago.svg'}
};
const terms={'1m':1,'2m':2,'3m':3,'6m':6,'12m':12};
const countries='MX US CA GB ES DE FR IT PT NL BE CH AT IE AU NZ AR BR CL CO PE EC UY PY BO CR PA DO GT SV HN NI VE PR IN ID PH TH MY SG JP KR TW HK ZA NG KE EG MA AE SA TR PL CZ SE NO DK FI RO GR HU UA IL'.split(' ');
const content={
 es:{kicker:'SP-DECODE · TIENDA',title:'Herramientas para cada etapa.',lead:'Elige tu acceso, revisa el plazo y conoce el precio antes de pagar. Sin cargos ocultos por elegir una pasarela.',
   online:'SP-DECODE Online',onlineLead:'Empieza sin pagar ni crear una cuenta.',offline:'SP-DECODE Offline',offlineLead:'Descifrado local desde Android, sujeto a activación.',api:'API para desarrolladores',apiLead:'Conecta tu aplicación con el motor de SP-DECODE.',
   featureOnline:['Uso gratuito sin iniciar sesión','Catálogos de servidores compatibles','Funciones actuales de Android'],
   featureOffline:['Licencia personal hasta 3 dispositivos','Funciona sin conexión después de activar','Sin anuncios en la versión Offline'],
   featureApi:['Clave individual y una IP pública autorizada','Cuota diaria configurable','Periodo definido por el plan seleccionado'],
   plan:'Elige una duración',total:'Precio del plan',from:'Disponible desde',notSet:'Sin precio publicado',notReady:'No disponible para compra',free:'Gratis',month:'mes',months:'meses',days:'días',perpetual:'Pago único',custom:'Plan actual',discount:'Ahorra',learn:'Ver condiciones',select:'Revisar este plan',explore:'Explorar Online',
   checkout:'Revisa tu compra',checkoutText:'Los impuestos aplicables se calcularán antes de confirmar. El precio del producto no cambia por elegir otro proveedor.',
   payments:'Opciones de pago',paymentsNote:'Los proveedores se habilitan individualmente. Las tarjetas y wallets dependen de tu país, moneda y dispositivo.',pendingProvider:'En configuración',
   safe:'Pago seguro',safeBody:'El pago se realiza en la página del proveedor. No recibimos los datos completos de tu tarjeta.',
   delivered:'Todo en tu cuenta',deliveredBody:'Cuando el proveedor confirma el pago, tus pedidos y accesos aparecen en sus respectivas secciones.',
   faq:'Preguntas frecuentes',questions:[['¿Online requiere comprar?','No. Puedes usar las funciones gratuitas de Android sin registrarte.'],['¿Por qué hay planes sin precio?','Cada moneda y duración se publica únicamente cuando el administrador define un importe real.'],['¿Ya se venden licencias Offline?','Las ventas seguirán bloqueadas hasta que la activación de licencias funcione en la APK.'],['¿Los precios incluyen impuestos?','El total fiscal se calcula según el destino y se muestra antes de pagar.']],
   checkoutCountry:'País de facturación',checkoutRegion:'Estado o región',checkoutIp:'IP pública de tu servidor',review:'Calcular total',continue:'Continuar al pago',currency:'Moneda',subtotal:'Subtotal',tax:'Impuestos aplicables',amount:'Total',close:'Cerrar',signIn:'Inicia sesión para comprar y administrar tus accesos.',signinButton:'Iniciar sesión con Google',termsAccept:'Acepto los términos de compra y la política de privacidad.',preview:'Aún no se puede comprar este plan. Configura el precio, la pasarela y los requisitos de activación.',taxProvider:'El impuesto definitivo se calculará en la pasarela.',sandbox:'Compras de prueba: no generan cargos reales ni accesos de producción.'},
 en:{kicker:'SP-DECODE · STORE',title:'Tools for every stage.',lead:'Choose your access, compare terms and review the price before checkout. No provider-specific surcharge.',
   online:'SP-DECODE Online',onlineLead:'Get started without payment or an account.',offline:'SP-DECODE Offline',offlineLead:'Local Android decoding, subject to license activation.',api:'Developer API',apiLead:'Connect your application to SP-DECODE.',
   featureOnline:['Free to use without an account','Compatible server catalogs','Current Android features'],
   featureOffline:['Personal license, up to 3 devices','Works offline after activation','No ads in the Offline app'],
   featureApi:['Individual key bound to one public IP','Configurable daily quota','Access duration defined by the chosen plan'],
   plan:'Choose a term',total:'Plan price',from:'Available from',notSet:'Price not published',notReady:'Not available for purchase',free:'Free',month:'month',months:'months',days:'days',perpetual:'One-time payment',custom:'Current plan',discount:'Save',learn:'View details',select:'Review this plan',explore:'Explore Online',
   checkout:'Review your purchase',checkoutText:'Applicable taxes are calculated before confirmation. Product prices do not change by payment provider.',
   payments:'Payment options',paymentsNote:'Providers are enabled individually. Cards and wallets depend on your country, currency and device.',pendingProvider:'Setting up',
   safe:'Secure checkout',safeBody:'Checkout runs on the provider website. Your full card details are not sent to us.',
   delivered:'All in your account',deliveredBody:'Once payment is confirmed, orders and entitlements appear in their own sections.',
   faq:'Common questions',questions:[['Is Online free?','Yes. You can use Android free features without signing in.'],['Why are some terms unpriced?','Prices are only published once the operator enters the real amount for each term and currency.'],['Can I buy an Offline license yet?','Sales remain locked until license activation works in the APK.'],['Are taxes included?','Applicable taxes are calculated for your location and shown before you pay.']],
   checkoutCountry:'Billing country',checkoutRegion:'State or region',checkoutIp:'Your server public IP',review:'Calculate total',continue:'Continue to checkout',currency:'Currency',subtotal:'Subtotal',tax:'Applicable tax',amount:'Total',close:'Close',signIn:'Sign in to buy and manage your access.',signinButton:'Sign in with Google',termsAccept:'I accept the purchase terms and privacy policy.',preview:'This plan cannot be purchased yet. Pricing, payments and license activation need to be configured.',taxProvider:'Final tax will be calculated by the provider.',sandbox:'Test purchases: no real charges or production access.'}
};
function ProviderMark({id,lang,detail=false}){const p=providers[id];return <span className="sp-provider-mark"><span className="sp-provider-logo"><img src={p.asset} alt="" width="22" height="22"/></span><span><strong>{p.name}</strong>{detail&&<small>{p.detail[lang]}</small>}</span></span>;}
function termLabel(p,t,lang){if(p.id==='base')return p.title==='lifetime'?t.perpetual:t.custom;const n=terms[p.id];return n===1?'1 '+t.month:n+' '+t.months;}
function savings(product,plan,currency){const monthly=product.plans?.find(p=>p.id==='1m')?.prices?.[currency];const count=terms[plan.id];const amount=plan.prices?.[currency];if(!count||count===1||!monthly||!amount)return 0;return Math.max(0,Math.round(100*(1-amount/(monthly*count))));}
function PriceOptions({product,currency,selection,onSelect,lang,t}){
 const options=product?.plans||[];
 return <div className="sp-term-group" aria-label={t.plan}><div className="sp-term-heading">{t.plan}</div><div className="sp-terms">
  {options.map(plan=>{const amount=plan.prices?.[currency],discount=savings(product,plan,currency);return <button key={plan.id} type="button" className={'sp-term '+(selection===plan.id?'selected':'')+(!amount?' unpriced':'')} onClick={()=>onSelect(plan.id)} aria-pressed={selection===plan.id}>
    <span>{termLabel(plan,t,lang)}</span><strong>{amount?money(amount,currency,lang):'—'}</strong>{discount>0&&<small>{t.discount} {discount}%</small>}
   </button>;})}
 </div></div>;
}
export default function Storefront(){
 const {lang}=usePublicLocale(),t=content[lang],es=lang==='es';
 const [data,setData]=useState(null),[account,setAccount]=useState(null),[error,setError]=useState('');
 const [currency,setCurrency]=useState('USD'),[termsSelected,setTermsSelected]=useState({'offline-3':'base','api-ip':'1m'});
 const [selected,setSelected]=useState(null),[term,setTerm]=useState('base'),[provider,setProvider]=useState('stripe'),[country,setCountry]=useState('MX'),[region,setRegion]=useState(''),[ip,setIp]=useState(''),[accepted,setAccepted]=useState(false),[quote,setQuote]=useState(null),[busy,setBusy]=useState(false);
 const dialog=useRef(null),idempotency=useRef(null);
 useEffect(()=>{let alive=true;Promise.all([shopFetch('/api/store/catalog'),shopFetch('/api/account')]).then(([a,b])=>{if(alive){setData(a);setAccount(b);setError('');}}).catch(()=>{if(alive)setError(errorMessage('',lang));});return()=>{alive=false;};},[lang]);
 useEffect(()=>{setQuote(null);idempotency.current=null;},[currency,term,provider,country,region,ip,selected]);
 const labelFor=(id)=>id==='offline-3'?t.offline:t.api;
 function open(product){if(!product)return;const option=termsSelected[product.id]||'base';setSelected(product);setTerm(option);setAccepted(false);setError('');setQuote(null);setProvider(product.providers?.find(x=>x!=='mercadopago'||currency==='MXN')||'stripe');dialog.current?.showModal();}
 async function review(){setBusy(true);setError('');try{setQuote(await shopFetch('/api/store/quote',{product:selected.id,term,currency,country,region,provider}));}catch(e){setError(errorMessage(e.message,lang));}finally{setBusy(false);}}
 async function pay(){setBusy(true);setError('');try{idempotency.current??=crypto.randomUUID();const out=await shopFetch('/api/store/checkout',{product:selected.id,term,provider,currency,country,region,allowedIp:ip,version:quote.version,idempotencyKey:idempotency.current,acceptedTerms:'2026-11-10'});window.location.assign(out.url||'/orders?order='+out.orderId);}catch(e){setError(errorMessage(e.message,lang));setBusy(false);}}
 const names=new Intl.DisplayNames([lang],{type:'region'}),picked=selected?.plans?.find(p=>p.id===term),pickedPrice=picked?.prices?.[currency],canCheckout=Boolean(selected?.available&&picked?.available&&pickedPrice&&selected?.providers?.some(id=>id===provider)&&!(provider==='mercadopago'&&currency!=='MXN'));
 const productCards=[{id:'online',label:t.online,lead:t.onlineLead,features:t.featureOnline},{id:'offline-3',label:t.offline,lead:t.offlineLead,features:t.featureOffline},{id:'api-ip',label:t.api,lead:t.apiLead,features:t.featureApi}];
 return <main id="main" className="sp-public-main sp-shop sp-store-redesign">
  <section className="sp-container sp-store-hero"><div><span className="sp-kicker">{t.kicker}</span><h1>{t.title}</h1><p>{t.lead}</p><div className="sp-store-promise"><span>{es?'Precios claros':'Clear prices'}</span><span>{es?'Compra protegida':'Secure checkout'}</span><span>{es?'Acceso desde tu cuenta':'Your account, your access'}</span></div></div><label className="sp-store-currency">{t.currency}<select value={currency} onChange={e=>setCurrency(e.target.value)}><option value="USD">USD</option><option value="MXN">MXN</option><option value="EUR">EUR</option></select></label></section>
  {data&&!data.live&&data.products.some(p=>p.available)&&<p className="sp-container sp-soft-notice" role="status">{t.sandbox}</p>}
  {error&&!selected&&<p role="alert" className="sp-container sp-form-error">{error}</p>}
  <section className="sp-container sp-store-grid" aria-label={t.title}>
   {productCards.map(card=>{const product=data?.products?.find(p=>p.id===card.id),plan=product?.plans?.find(p=>p.id===(termsSelected[card.id]||'base'))||product?.plans?.[0],amount=plan?.prices?.[currency];
   return <article key={card.id} className={'sp-store-card '+(card.id==='offline-3'?'spotlight':'')}>
    <div className="sp-store-card-head"><span className="sp-store-card-icon"><ProductIcon type={card.id}/></span><span className="sp-store-card-category">{card.id==='online'?'ANDROID · FREE':card.id==='offline-3'?'ANDROID · OFFLINE':'DEVELOPERS · API'}</span></div><h2>{card.label}</h2><p>{card.lead}</p>
    {card.id==='online'?<div className="sp-store-free">{t.free}<small>{es?'Para siempre':'Forever'}</small></div>:<>
      <div className="sp-store-price-line"><span>{t.total}</span><strong>{amount?money(amount,currency,lang):t.notSet}</strong></div>
      <PriceOptions product={product} currency={currency} selection={plan?.id||'base'} onSelect={id=>setTermsSelected(x=>({...x,[card.id]:id}))} lang={lang} t={t}/>
      <div className="sp-store-plan-meta">{plan?.days?plan.days+' '+t.days:t.perpetual}{card.id==='api-ip'&&product?.quota?' · '+product.quota.toLocaleString(lang)+' / '+t.days:''}</div>
    </>}
    <ul className="sp-store-features">{card.features.map(value=><li key={value}>{value}</li>)}</ul>
    {card.id==='online'?<Link className="sp-shop-button secondary" href="/#gallery">{t.explore}</Link>:<button type="button" className="sp-shop-button" disabled={!product} onClick={()=>open(product)}>{plan?.available&&amount?t.select:t.learn}</button>}
    {card.id!=='online'&&(!plan?.available||!amount)&&<small className="sp-store-unavailable">{t.notReady}</small>}
   </article>;})}
  </section>
  <section className="sp-container sp-store-payments"><div className="sp-store-payments-intro"><span className="sp-kicker">CHECKOUT</span><h2>{t.payments}</h2><p>{t.checkoutText}</p></div><div className="sp-payment-logo-grid">{Object.keys(providers).map(id=><div className="sp-payment-logo-card" key={id}><ProviderMark id={id} lang={lang} detail/><small>{data?.products?.some(p=>p.providers?.includes(id))?(es?'Configurado':'Configured'):t.pendingProvider}</small></div>)}</div><p className="sp-store-method-note">{t.paymentsNote}</p></section>
  <section className="sp-container sp-shop-assurances"><article><div className="sp-assurance-symbol">✓</div><h3>{t.safe}</h3><p>{t.safeBody}</p></article><article><div className="sp-assurance-symbol">↗</div><h3>{t.delivered}</h3><p>{t.deliveredBody}</p></article></section>
  <section className="sp-container sp-section sp-shop-faq"><span className="sp-kicker">FAQ</span><h2>{t.faq}</h2>{t.questions.map(([q,a])=><details key={q}><summary>{q}<span aria-hidden="true">+</span></summary><p>{a}</p></details>)}</section>
  <dialog ref={dialog} className="sp-checkout sp-checkout-modern" aria-labelledby="sp-checkout-title" onClose={()=>{setSelected(null);setError('');}}>
   <div className="sp-checkout-head"><span className="sp-kicker">SP-DECODE · CHECKOUT</span><button className="sp-dialog-close" type="button" aria-label={t.close} onClick={()=>dialog.current?.close()}>×</button></div>
   {selected&&<><h2 id="sp-checkout-title">{labelFor(selected.id)}</h2><p>{t.checkout}</p><PriceOptions product={selected} currency={currency} selection={term} onSelect={setTerm} lang={lang} t={t}/>
    <div className="sp-selected-price"><span>{termLabel(picked||{id:'base'},t,lang)}</span><strong>{pickedPrice?money(pickedPrice,currency,lang):t.notSet}</strong></div>
    {!canCheckout?<div className="sp-soft-notice">{t.preview}</div>:!account?.user?<div className="sp-checkout-signin"><p>{t.signIn}</p><Link href="/login?next=/store" className="sp-shop-button">{t.signinButton}</Link></div>:<>
      <div className="sp-checkout-methods">{selected.providers.filter(id=>id!=='mercadopago'||currency==='MXN').map(id=><label key={id} className={'sp-checkout-method '+(provider===id?'chosen':'')}><input type="radio" name="provider" value={id} checked={provider===id} onChange={()=>setProvider(id)}/><ProviderMark id={id} lang={lang} detail/></label>)}</div>
      <div className="sp-form-grid"><label>{t.checkoutCountry}<select value={country} onChange={e=>setCountry(e.target.value)}>{countries.map(code=><option key={code} value={code}>{names.of(code)}</option>)}</select></label><label>{t.checkoutRegion}<input type="text" maxLength={12} value={region} autoComplete="address-level1" onChange={e=>setRegion(e.target.value.toUpperCase())}/></label></div>
      {selected.id==='api-ip'&&<label>{t.checkoutIp}<input type="text" value={ip} placeholder="IPv4 / IPv6" autoComplete="off" spellCheck="false" onChange={e=>setIp(e.target.value.trim())}/></label>}
      {!quote?<button className="sp-shop-button" disabled={busy} onClick={review}>{busy?'…':t.review}</button>:<><dl className="sp-order-total"><div><dt>{t.subtotal}</dt><dd>{money(quote.subtotal,currency,lang)}</dd></div><div><dt>{quote.taxLabel||t.tax}</dt><dd>{money(quote.tax,currency,lang)}</dd></div><div className="total"><dt>{t.amount}</dt><dd>{money(quote.total,currency,lang)}</dd></div></dl>{quote.automaticTax&&<small>{t.taxProvider}</small>}<label className="sp-consent"><input type="checkbox" checked={accepted} onChange={e=>setAccepted(e.target.checked)}/><span>{t.termsAccept} <Link href="/terms" target="_blank">{es?'Leer':'Read'}</Link></span></label><button className="sp-shop-button" disabled={busy||!accepted} onClick={pay}>{busy?'…':t.continue}</button></>}
     </>}
     {error&&<p role="alert" className="sp-form-error">{error}</p>}
   </>}
  </dialog>
 </main>;
}
