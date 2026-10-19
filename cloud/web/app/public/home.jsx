"use client";
import Link from "next/link";
import {useState} from "react";
import {usePublicLocale} from "./site-chrome.jsx";
const content={
 es:{
  tag:"Aplicación para Android",title:"Tus configuraciones, más claras.",
  intro:"Explora e interpreta configuraciones VPN desde tu dispositivo Android con una experiencia sencilla, moderna y familiar.",
  download:"Descargar para Android",note:"Descargas y versiones disponibles únicamente en el canal oficial.",
  explore:"Explora la aplicación",exploreText:"Conoce las pantallas reales de SP-DECODE. Desliza o usa los controles para ver las cuatro capturas.",
  features:"Lo esencial, en un solo lugar",
  featuresText:"Una interfaz diseñada para consultar tus configuraciones y organizar tus resultados sin complicaciones.",
  items:[["Archivos y textos","Selecciona archivos o introduce texto desde la aplicación."],["Historial","Consulta y administra tus resultados guardados."],["Formatos","Explora los formatos disponibles desde un catálogo."],["Server VPN","Accede a las funciones de catálogos compatibles."]],
  privacyTitle:"Información clara y accesible",privacyText:"Consulta cómo funciona el servicio, qué información procesa y cuáles son las condiciones de uso.",
  privacy:"Leer privacidad",terms:"Ver términos",support:"Contactar soporte",
  screenNames:["Inicio","Historial","Formatos","Ajustes"],previous:"Captura anterior",next:"Siguiente captura",capture:"Captura",of:"de"
 },
 en:{
  tag:"Android application",title:"Make your configurations clearer.",
  intro:"Explore and interpret VPN configurations from your Android device through a simple, modern and familiar experience.",
  download:"Download for Android",note:"Downloads and available versions are provided only through the official release channel.",
  explore:"Explore the app",exploreText:"Take a look at the real SP-DECODE screens. Swipe or use the controls to browse all four screenshots.",
  features:"Everything you need, in one place",featuresText:"An interface designed to inspect your configurations and organize your results with less effort.",
  items:[["Files and text","Select configuration files or paste text inside the application."],["History","Review and manage your saved results."],["Formats","Browse supported formats in the catalog."],["Server VPN","Access compatible remote catalog features."]],
  privacyTitle:"Clear, accessible information",privacyText:"Learn how the service works, what information it processes and the conditions of use.",
  privacy:"Read privacy policy",terms:"View terms",support:"Contact support",
  screenNames:["Home","History","Formats","Settings"],previous:"Previous screenshot",next:"Next screenshot",capture:"Screenshot",of:"of"
 }};
const screens=["01-home.webp","02-history.webp","03-formats.webp","04-settings.webp"];
function Gallery({t}){
 const [index,setIndex]=useState(0);
 const change=(n)=>setIndex((n+screens.length)%screens.length);
 let startX=null;
 return <div className="sp-gallery" aria-roledescription="carousel" aria-label={t.explore}>
  <div className="sp-gallery-viewport" onTouchStart={event=>{startX=event.touches[0].clientX;}}
    onTouchEnd={event=>{if(startX===null)return;const dx=event.changedTouches[0].clientX-startX;if(Math.abs(dx)>45)change(index+(dx<0?1:-1));startX=null;}}>
   <div className="sp-gallery-track" style={{transform:`translateX(-${index*100}%)`}}>
    {screens.map((screen,i)=><figure key={screen} className="sp-screen">
     <img src={`/screenshots/${screen}`} alt={`SP-DECODE · ${t.screenNames[i]}`} width="674" height="1536" loading={i===0?"eager":"lazy"}/>
     <figcaption>{t.screenNames[i]}</figcaption>
    </figure>)}
   </div>
  </div>
  <div className="sp-gallery-controls">
   <button type="button" onClick={()=>change(index-1)} aria-label={t.previous}>←</button>
   <div className="sp-gallery-dots">{screens.map((_,i)=><button key={i} type="button" onClick={()=>change(i)} aria-label={`${t.capture} ${i+1} ${t.of} 4`} aria-current={i===index?"true":undefined}/>)}</div>
   <button type="button" onClick={()=>change(index+1)} aria-label={t.next}>→</button>
  </div>
  <p className="sp-gallery-count" aria-live="polite">{t.capture} {index+1} {t.of} 4</p>
 </div>;
}
export default function Home(){
 const {lang}=usePublicLocale();const t=content[lang];
 return <main id="main" className="sp-public-main">
  <section className="sp-container sp-hero">
   <div className="sp-hero-copy"><span className="sp-kicker"><span aria-hidden="true" className="sp-small-dot"/> {t.tag}</span>
    <h1>SP-DECODE</h1><h2>{t.title}</h2><p>{t.intro}</p>
    <a className="sp-button sp-button-primary" href="https://github.com/Gh0stDeveloper/SP-DECODE/releases" target="_blank" rel="noopener noreferrer">
     <svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" aria-hidden="true"><path d="M12 3v12m-5-5 5 5 5-5M4 17v4h16v-4"/></svg>{t.download}</a>
    <small className="sp-hint">{t.note}</small>
   </div>
   <div className="sp-hero-app" aria-label="SP-DECODE"><img src="/icon.svg" alt="SP-DECODE" width="128" height="128"/><strong>SP-DECODE</strong><span>Configuration decoder</span><div className="sp-hero-device-line"/></div>
  </section>
  <section className="sp-section sp-container" id="gallery"><div className="sp-section-heading"><h2>{t.explore}</h2><p>{t.exploreText}</p></div><Gallery t={t}/></section>
  <section className="sp-section sp-container" id="features"><div className="sp-section-heading"><h2>{t.features}</h2><p>{t.featuresText}</p></div>
   <div className="sp-feature-grid">{t.items.map(([title,description],i)=><article key={title} className="sp-feature-card"><span className="sp-feature-number">{String(i+1).padStart(2,"0")}</span><h3>{title}</h3><p>{description}</p></article>)}</div>
  </section>
  <section className="sp-section sp-container sp-callout"><div><h2>{t.privacyTitle}</h2><p>{t.privacyText}</p></div><div className="sp-cta-links"><Link href="/privacy">{t.privacy}</Link><Link href="/terms">{t.terms}</Link><Link href="/support">{t.support}</Link></div></section>
 </main>;
}
