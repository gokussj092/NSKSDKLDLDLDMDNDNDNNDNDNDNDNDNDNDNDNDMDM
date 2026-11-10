"use client";
import Link from "next/link";
import {usePathname} from "next/navigation";
import {useEffect,useRef,useState,createContext,useContext,useCallback} from "react";
import "./public.css";

const publicRoutes=new Set(["/","/privacy","/terms","/support","/store","/login","/account","/orders","/receipts","/products","/credits","/features","/docs","/status"]);
const LocaleContext=createContext({lang:"es",setLang:()=>{}});
const SessionContext=createContext({account:null,refreshAccount:async()=>{}});
export const usePublicLocale=()=>useContext(LocaleContext);
export const usePublicSession=()=>useContext(SessionContext);
const labels={
 es:{home:"Inicio",features:"Funciones",store:"Tienda",account:"Mi perfil",orders:"Mis compras",receipts:"Mis recibos",products:"Mis productos",credits:"Mis créditos",signIn:"Iniciar sesión",signOut:"Cerrar sesión",privacy:"Privacidad",terms:"Términos",support:"Soporte",language:"Idioma",credit:"Creado por Ghost Developer",official:"Sitio oficial de SP-DECODE para Android",menu:"Abrir menú",close:"Cerrar menú",public:"Explorar SP-DECODE",private:"Mi espacio",guest:"Accede para administrar tus compras y licencias",signed:"Cuenta conectada"},
 en:{home:"Home",features:"Features",store:"Store",account:"My profile",orders:"Purchases",receipts:"Receipts",products:"My products",credits:"My credits",signIn:"Sign in",signOut:"Sign out",privacy:"Privacy",terms:"Terms",support:"Support",language:"Language",credit:"Created by Ghost Developer",official:"Official SP-DECODE website for Android",menu:"Open menu",close:"Close menu",public:"Explore SP-DECODE",private:"My space",guest:"Sign in to manage purchases and licenses",signed:"Signed-in account"}
};
function MenuIcon(){return <svg aria-hidden="true" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round"><path d="M4 7h16M4 12h16M4 17h16"/></svg>}
function Chevron(){return <svg aria-hidden="true" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7"><path d="m9 5 7 7-7 7"/></svg>}
function Avatar({user,size=38}){return <span className="sp-user-avatar" style={{width:size,height:size}}>{user?.avatar?<img src={user.avatar} alt="" referrerPolicy="no-referrer"/>:<span>{(user?.name||"?").slice(0,1).toUpperCase()}</span>}</span>}
function PublicChrome({children}){
 const pathname=usePathname(),[lang,setLang]=useState("es"),[account,setAccount]=useState(null);
 const [menuOpen,setMenuOpen]=useState(false),[signingOut,setSigningOut]=useState(false);
 const menuButton=useRef(null),sidebar=useRef(null),startTouch=useRef(null);
 const refreshAccount=useCallback(async()=>{try{const r=await fetch('/api/account',{credentials:'same-origin',cache:'no-store'});const json=r.ok?await r.json():null;setAccount(json?.user||null);}catch{setAccount(null);}},[]);
 useEffect(()=>{refreshAccount();window.addEventListener('focus',refreshAccount);return()=>window.removeEventListener('focus',refreshAccount);},[pathname,refreshAccount]);
 useEffect(()=>{let saved;try{saved=localStorage.getItem("spdecode.site.language");}catch{}setLang(saved==="es"||saved==="en"?saved:navigator.language?.toLowerCase().startsWith("es")?"es":"en");},[]);
 const select=useCallback(value=>{if(value!=="es"&&value!=="en")return;setLang(value);try{localStorage.setItem("spdecode.site.language",value);}catch{}},[]);
 useEffect(()=>{document.documentElement.lang=lang;return()=>{document.documentElement.lang="es";};},[lang]);
 useEffect(()=>{setMenuOpen(false);},[pathname]);
 useEffect(()=>{if(!menuOpen)return;const before=document.body.style.overflow;document.body.style.overflow='hidden';sidebar.current?.querySelector('button,a')?.focus();const onKey=e=>{if(e.key==='Escape')setMenuOpen(false);if(e.key==='Tab'){const controls=[...sidebar.current.querySelectorAll('a,button,select')].filter(el=>!el.disabled);if(!controls.length)return;const first=controls[0],last=controls.at(-1);if(e.shiftKey&&document.activeElement===first){e.preventDefault();last.focus();}else if(!e.shiftKey&&document.activeElement===last){e.preventDefault();first.focus();}}};window.addEventListener('keydown',onKey);return()=>{document.body.style.overflow=before;window.removeEventListener('keydown',onKey);menuButton.current?.focus();};},[menuOpen]);
 useEffect(()=>{const onStart=e=>{if(e.touches.length!==1)return;const x=e.touches[0].clientX;startTouch.current={x,y:e.touches[0].clientY,open:menuOpen};};const onEnd=e=>{const s=startTouch.current;startTouch.current=null;if(!s||!e.changedTouches.length)return;const dx=e.changedTouches[0].clientX-s.x,dy=e.changedTouches[0].clientY-s.y;if(Math.abs(dy)>Math.abs(dx)||Math.abs(dx)<75)return;if(s.open&&dx<0)setMenuOpen(false);else if(!s.open&&((s.x<42&&dx>0)||(s.x>window.innerWidth-42&&dx<0)))setMenuOpen(true);};document.addEventListener('touchstart',onStart,{passive:true});document.addEventListener('touchend',onEnd,{passive:true});return()=>{document.removeEventListener('touchstart',onStart);document.removeEventListener('touchend',onEnd);};},[menuOpen]);
 const t=labels[lang],publicLinks=[[t.home,'/'],[t.features,'/#features'],[t.store,'/store'],[t.support,'/support']];const privateLinks=[[t.account,'/account'],[t.orders,'/orders'],[t.receipts,'/receipts'],[t.products,'/products'],[t.credits,'/credits']];
 async function signOut(){setSigningOut(true);try{const {authClient}=await import('./shop-common.jsx');const result=await authClient.signOut();if(result.error)throw Error(result.error.code);setAccount(null);setMenuOpen(false);window.location.assign('/login');}catch{setSigningOut(false);}}
 return <LocaleContext.Provider value={{lang,setLang:select}}><SessionContext.Provider value={{account,refreshAccount}}>
  <div className="sp-public-frame">
   <header className="sp-public-header"><div className="sp-container sp-header-row sp-header-modern">
    <div className="sp-header-leading"><button ref={menuButton} type="button" className="sp-menu-button" onClick={()=>setMenuOpen(true)} aria-label={t.menu} aria-expanded={menuOpen} aria-controls="sp-site-drawer"><MenuIcon/></button>
     <Link className="sp-logo" href="/" aria-label="SP-DECODE"><img src="/icon.svg" alt="" width="43" height="43"/><span><strong>SP-DECODE</strong><small>Configuration decoder</small></span></Link></div>
    <div className="sp-header-actions"><Link className="sp-header-store" href="/store">{t.store}</Link>
     <label className="sp-language"><span>{t.language}</span><select aria-label={t.language} value={lang} onChange={e=>select(e.target.value)}><option value="es">ES</option><option value="en">EN</option></select></label>
     <Link className="sp-account-link" href={account?'/account':'/login'}>{account?<><Avatar user={account} size={28}/><span className="sp-header-username">@{account.username}</span></>:t.signIn}</Link></div>
   </div></header>
   {menuOpen&&<div className="sp-drawer-layer"><button className="sp-drawer-scrim" type="button" aria-label={t.close} onClick={()=>setMenuOpen(false)}/><aside id="sp-site-drawer" ref={sidebar} className="sp-site-drawer" role="dialog" aria-modal="true" aria-label={t.menu}>
    <div className="sp-drawer-top"><Link href="/" className="sp-drawer-brand"><img src="/icon.svg" width="36" height="36" alt=""/><strong>SP-DECODE</strong></Link><button type="button" className="sp-drawer-close" aria-label={t.close} onClick={()=>setMenuOpen(false)}>×</button></div>
    <div className="sp-drawer-user">{account?<><Avatar user={account} size={54}/><div><strong>{account.name}</strong><small>@{account.username}</small><span>{t.signed}</span></div></>:<><div className="sp-guest-avatar">G</div><div><strong>{t.signIn}</strong><small>{t.guest}</small></div></>}</div>
    {!account&&<Link href="/login" className="sp-drawer-login">{t.signIn}<Chevron/></Link>}
    <nav className="sp-drawer-nav" aria-label={t.public}><span>{t.public}</span>{publicLinks.map(([label,href])=><Link key={href} className={pathname===href?'active':''} href={href}>{label}<Chevron/></Link>)}</nav>
    {account&&<nav className="sp-drawer-nav" aria-label={t.private}><span>{t.private}</span>{privateLinks.map(([label,href])=><Link key={href} className={pathname===href?'active':''} href={href}>{label}<Chevron/></Link>)}<button type="button" disabled={signingOut} onClick={signOut}>{t.signOut}<Chevron/></button></nav>}
    <div className="sp-drawer-bottom"><Link href="/privacy">{t.privacy}</Link><Link href="/terms">{t.terms}</Link><p>SP-DECODE · Ghost Developer</p></div>
   </aside></div>}
   {children}
   <footer className="sp-public-footer"><div className="sp-container sp-footer-grid"><div className="sp-footer-brand"><img src="/icon.svg" width="35" height="35" alt=""/><strong>SP-DECODE</strong><p>{t.official}</p><small>{t.credit}</small></div><nav aria-label="Legal"><Link href="/privacy">{t.privacy}</Link><Link href="/terms">{t.terms}</Link><Link href="/support">{t.support}</Link></nav></div><div className="sp-container sp-footer-bottom">© {new Date().getFullYear()} SP-DECODE · Ghost Developer</div></footer>
  </div>
 </SessionContext.Provider></LocaleContext.Provider>;
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
function AdminChrome({children,path}){
 const isLogin=path==="/admin/login";
 return <div className="sp-admin-frame">
  <header className="sp-admin-topbar">
   <div className="sp-admin-topbar-inner">
    <Link className="sp-admin-brand" href={isLogin?"/":"/admin"} aria-label="SP-DECODE Administración">
     <img src="/icon.svg" width="43" height="43" alt=""/>
     <span><strong>SP-DECODE</strong><small>Administración Cloud</small></span>
    </Link>
    <span className="sp-admin-topbar-label">{isLogin?"Acceso restringido":"Consola privada"}</span>
   </div>
  </header>
  {children}
  <footer className="sp-admin-footer">
   <span>SP-DECODE · Ghost Developer</span>
   <nav aria-label="Documentos legales"><Link href="/privacy">Privacidad</Link><Link href="/terms">Términos</Link><Link href="/support">Soporte</Link></nav>
  </footer>
 </div>;
}
export default function SiteChrome({children}){
 const pathname=usePathname();
 if(pathname?.startsWith("/admin"))return <AdminChrome path={pathname}>{children}</AdminChrome>;
 return publicRoutes.has(pathname)?<PublicChrome>{children}</PublicChrome>:<LegacyChrome>{children}</LegacyChrome>;
}
