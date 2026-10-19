"use client";
import Link from "next/link";
import {usePathname} from "next/navigation";
import {useEffect,useState,createContext,useContext} from "react";
import "./public.css";
const publicRoutes=new Set(["/","/privacy","/terms","/support"]);
const LocaleContext=createContext({lang:"es",setLang:()=>{}});
export const usePublicLocale=()=>useContext(LocaleContext);
const labels={
 es:{home:"Inicio",privacy:"Privacidad",terms:"Términos",support:"Soporte",download:"Descargar",language:"Idioma",credit:"Creado por Ghost Developer",official:"Sitio oficial de SP-DECODE para Android",skip:"Saltar al contenido"},
 en:{home:"Home",privacy:"Privacy",terms:"Terms",support:"Support",download:"Download",language:"Language",credit:"Created by Ghost Developer",official:"Official SP-DECODE website for Android",skip:"Skip to content"},
};
export function PublicChrome({children}){
 const [lang,setLang]=useState("es");
 useEffect(()=>{
   let saved;try{saved=localStorage.getItem("spdecode.site.language");}catch{}
   const detected=saved==="es"||saved==="en"?saved:
     (navigator.language?.toLowerCase().startsWith("es")?"es":"en");
   setLang(detected);
 },[]);
 function select(value){
   if(value!=="es"&&value!=="en")return;
   setLang(value);
   try{localStorage.setItem("spdecode.site.language",value);}catch{}
 }
 useEffect(()=>{document.documentElement.lang=lang;return()=>{document.documentElement.lang="es";};},[lang]);
 const t=labels[lang];
 return <LocaleContext.Provider value={{lang,setLang:select}}>
  <div className="sp-public-frame">
   <header className="sp-public-header">
    <div className="sp-container sp-header-row">
     <Link className="sp-logo" href="/" aria-label="SP-DECODE"><img src="/icon.svg" alt="" width="43" height="43"/><span><strong>SP-DECODE</strong><small>Configuration decoder</small></span></Link>
     <nav className="sp-nav" aria-label="Public">
      <Link href="/">{t.home}</Link><Link href="/privacy">{t.privacy}</Link>
      <Link href="/terms">{t.terms}</Link><Link href="/support">{t.support}</Link>
     </nav>
     <label className="sp-language">{t.language}<select aria-label={t.language} value={lang} onChange={event=>select(event.target.value)}><option value="es">ES</option><option value="en">EN</option></select></label>
    </div>
   </header>
   {children}
   <footer className="sp-public-footer"><div className="sp-container sp-footer-grid">
    <div className="sp-footer-brand"><img src="/icon.svg" width="35" height="35" alt=""/><strong>SP-DECODE</strong>
      <p>{t.official}</p><small>{t.credit}</small></div>
    <nav aria-label="Legal"><Link href="/privacy">{t.privacy}</Link><Link href="/terms">{t.terms}</Link><Link href="/support">{t.support}</Link></nav>
   </div><div className="sp-container sp-footer-bottom">© {new Date().getFullYear()} SP-DECODE · Ghost Developer</div></footer>
  </div>
 </LocaleContext.Provider>;
}
const legacyLinks=[["Inicio","/"],["Funciones","/features"],["Documentación","/docs"],["Términos","/terms"],["Privacidad","/privacy"],["Estado","/status"]];
function LegacyChrome({children}){return <>
 <header className="header"><div className="shell head-inner">
  <Link className="brand" href="/" aria-label="SP-DECODE Cloud, inicio"><span className="brand-mark" aria-hidden="true">SP</span><span>SP-DECODE <span className="brand-secondary">Cloud</span></span></Link>
  <nav className="nav" aria-label="Navegación principal">{legacyLinks.map(([label,href])=><Link key={href} href={href}>{label}</Link>)}</nav>
 </div></header>
 {children}
 <footer className="footer"><div className="shell footer-layout">
  <div><div className="footer-brand">SP-DECODE Cloud</div><p>Infraestructura en desarrollo. El descifrado se ejecutará exclusivamente en el servidor.</p><span className="muted">Desarrollado por Ghost Developer.</span><p><a href="mailto:soporte@spdecode.xyz">soporte@spdecode.xyz</a></p></div>
  <div className="footer-links"><Link href="/features">Funciones</Link><Link href="/docs">Documentación</Link><Link href="/terms">Términos</Link><Link href="/privacy">Privacidad</Link><Link href="/status">Estado</Link><Link href="https://panel.spdecode.xyz/admin/login">Administración</Link></div>
 </div><div className="shell footer-last">SP-DECODE Cloud · Plataforma Android · Sin descifrado desde el navegador</div></footer>
 </>;}
export default function SiteChrome({children}){
 const pathname=usePathname();
 return publicRoutes.has(pathname)?<PublicChrome>{children}</PublicChrome>:<LegacyChrome>{children}</LegacyChrome>;
}
