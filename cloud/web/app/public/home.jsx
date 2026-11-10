"use client";
import Link from "next/link";
import {useRef} from "react";
import {usePublicLocale} from "./site-chrome.jsx";
const content={
 es:{
  tag:"Aplicación para Android",title:"Tus configuraciones, más claras.",
  intro:"Explora e interpreta configuraciones VPN desde tu dispositivo Android con una experiencia sencilla, moderna y familiar.",
  download:"Próximamente",play:"Google Play",note:"SP-DECODE estará disponible próximamente en Google Play.",
  explore:"Explora la aplicación",exploreText:"Desliza horizontalmente para explorar las cuatro pantallas reales de SP-DECODE.",
  features:"Lo esencial, en un solo lugar",
  featuresText:"Una interfaz diseñada para consultar tus configuraciones y organizar tus resultados sin complicaciones.",
  items:[["Archivos y textos","Selecciona archivos o introduce texto desde la aplicación."],["Historial","Consulta y administra tus resultados guardados."],["Formatos","Explora los formatos disponibles desde un catálogo."],["Server VPN","Accede a las funciones de catálogos compatibles."]],
  privacyTitle:"Información clara y accesible",privacyText:"Consulta cómo funciona el servicio, qué información procesa y cuáles son las condiciones de uso.",
  privacy:"Leer privacidad",terms:"Ver términos",support:"Contactar soporte",
  screenNames:["Inicio","Historial","Formatos","Ajustes"],capture:"Captura",of:"de"
 },
 en:{
  tag:"Android application",title:"Make your configurations clearer.",
  intro:"Explore and interpret VPN configurations from your Android device through a simple, modern and familiar experience.",
  download:"Coming soon",play:"Google Play",note:"SP-DECODE is coming soon to Google Play.",
  explore:"Explore the app",exploreText:"Swipe horizontally to explore all four real SP-DECODE screens.",
  features:"Everything you need, in one place",featuresText:"An interface designed to inspect your configurations and organize your results with less effort.",
  items:[["Files and text","Select configuration files or paste text inside the application."],["History","Review and manage your saved results."],["Formats","Browse supported formats in the catalog."],["Server VPN","Access compatible remote catalog features."]],
  privacyTitle:"Clear, accessible information",privacyText:"Learn how the service works, what information it processes and the conditions of use.",
  privacy:"Read privacy policy",terms:"View terms",support:"Contact support",
  screenNames:["Home","History","Formats","Settings"],capture:"Screenshot",of:"of"
 }};
const screens=["01-home.jpg","02-history.jpg","03-formats.jpg","04-settings.jpg"];
function Gallery({t}){
 // Native horizontal scroll handles swipes on touch screens and trackpads.
 // Mouse drag and keyboard arrows are available for desktop accessibility.
 const viewportRef=useRef(null);
 const drag=useRef(null);
 const stopDrag=event=>{
  const viewport=viewportRef.current;
  if(!viewport||!drag.current)return;
  drag.current=null;
  viewport.style.scrollSnapType="";
  viewport.style.cursor="";
  if(event.currentTarget.hasPointerCapture?.(event.pointerId))
   event.currentTarget.releasePointerCapture(event.pointerId);
 };
 const onPointerDown=event=>{
  if(event.pointerType!=="mouse"||event.button!==0)return;
  const viewport=event.currentTarget;
  if(viewport.scrollWidth<=viewport.clientWidth)return;
  drag.current={x:event.clientX,left:viewport.scrollLeft};
  viewport.style.scrollSnapType="none";
  viewport.style.cursor="grabbing";
  viewport.setPointerCapture(event.pointerId);
 };
 const onPointerMove=event=>{
  if(!drag.current||event.pointerType!=="mouse")return;
  event.currentTarget.scrollLeft=drag.current.left+drag.current.x-event.clientX;
 };
 const onKeyDown=event=>{
  if(event.key!=="ArrowRight"&&event.key!=="ArrowLeft")return;
  event.preventDefault();
  event.currentTarget.scrollBy({left:(event.key==="ArrowRight"?1:-1)*270,behavior:"smooth"});
 };
 return <div className="sp-gallery">
  <div ref={viewportRef} className="sp-gallery-viewport" role="region" aria-roledescription="carousel"
   aria-label={t.explore} tabIndex={0}
   onPointerDown={onPointerDown} onPointerMove={onPointerMove}
   onPointerUp={stopDrag} onPointerCancel={stopDrag} onLostPointerCapture={stopDrag}
   onKeyDown={onKeyDown}>
   <div className="sp-gallery-track">
    {screens.map((screen,i)=><figure key={screen} className="sp-screen" role="group"
     aria-label={t.capture+" "+(i+1)+" "+t.of+" "+screens.length+": "+t.screenNames[i]}>
     <img src={"/screenshots/"+screen} alt={"SP-DECODE · "+t.screenNames[i]}
      width="674" height="1536" loading={i===0?"eager":"lazy"} draggable={false}/>
     <figcaption>{t.screenNames[i]}</figcaption>
    </figure>)}
   </div>
  </div>
 </div>;
}
export default function Home(){
 const {lang}=usePublicLocale();const t=content[lang];
 return <main id="main" className="sp-public-main">
  <section className="sp-container sp-hero">
   <div className="sp-hero-copy"><span className="sp-kicker"><span aria-hidden="true" className="sp-small-dot"/> {t.tag}</span>
    <h1>SP-DECODE</h1><h2>{t.title}</h2><p>{t.intro}</p>
    <button className="sp-button sp-button-play-pending" type="button" disabled aria-disabled="true">
     <span className="sp-play-platform">{t.play}</span><strong>{t.download}</strong>
    </button>
    <small className="sp-hint">{t.note}</small>
   </div>
   <div className="sp-hero-app" aria-label="SP-DECODE"><img src="/icon.svg" alt="SP-DECODE" width="128" height="128"/><strong>SP-DECODE</strong><span>Configuration decoder</span><div className="sp-hero-device-line"/></div>
  </section>
  <section className="sp-section sp-container" id="gallery"><div className="sp-section-heading"><h2>{t.explore}</h2><p>{t.exploreText}</p></div><Gallery t={t}/></section>
  <section className="sp-section sp-container" id="features"><div className="sp-section-heading"><h2>{t.features}</h2><p>{t.featuresText}</p></div>
   <div className="sp-feature-grid">{t.items.map(([title,description],i)=><article key={title} className="sp-feature-card"><span className="sp-feature-number">{String(i+1).padStart(2,"0")}</span><h3>{title}</h3><p>{description}</p></article>)}</div>
  </section>
  <section className="sp-section sp-container sp-home-products"><div className="sp-section-heading"><span className="sp-kicker">SP-DECODE</span><h2>{lang==='es'?'A tu manera. A tu ritmo.':'Your workflow. Your pace.'}</h2><p>{lang==='es'?'Usa Online gratuitamente o explora los productos pensados para trabajar de forma local e integrar tus propios proyectos.':'Use Online for free, or explore products for working locally and integrating your own projects.'}</p></div>
   <div className="sp-home-products-grid"><article><span className="sp-kicker">ONLINE</span><h3>{lang==='es'?'Conecta y explora':'Connect and explore'}</h3><p>{lang==='es'?'Descifrado mediante el servidor, historial y catálogos desde Android. Las funciones gratuitas no requieren una cuenta.':'Server-based decoding, history and catalogs on Android. Free features do not require an account.'}</p><Link href="#gallery">{lang==='es'?'Ver la aplicación':'Explore the app'} →</Link></article>
    <article><span className="sp-kicker">OFFLINE</span><h3>{lang==='es'?'Trabaja en tu dispositivo':'Work on your device'}</h3><p>{lang==='es'?'Una licencia personal de pago único para hasta tres dispositivos. Sin anuncios y con resultados completos.':'A personal one-time license for up to three devices. No ads, with complete results.'}</p><Link href="/store">{lang==='es'?'Ver licencia Offline':'View Offline license'} →</Link></article>
    <article><span className="sp-kicker">DEVELOPERS</span><h3>{lang==='es'?'Integra tus herramientas':'Connect your tools'}</h3><p>{lang==='es'?'Acceso API con una clave propia, vinculación a una IP pública y límites definidos por tu plan.':'API access with a dedicated key, public-IP binding and plan-based limits.'}</p><Link href="/store">{lang==='es'?'Explorar acceso API':'Explore API access'} →</Link></article></div>
  </section>
  <section className="sp-section sp-container sp-callout"><div><h2>{t.privacyTitle}</h2><p>{t.privacyText}</p></div><div className="sp-cta-links"><Link href="/privacy">{t.privacy}</Link><Link href="/terms">{t.terms}</Link><Link href="/support">{t.support}</Link></div></section>
 </main>;
}
