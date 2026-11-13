"use client";
import Link from "next/link";
import {usePathname} from "next/navigation";
import {useEffect,useState} from "react";
export const groups=[
 {label:"General",links:[["Resumen","/admin","dashboard"],["Analítica","/admin/analytics","chart"],["Incidencias","/admin/reports","list"],["Solicitudes","/admin/requests","message"],["Diagnóstico","/admin/diagnostics","search"]]},
 {label:"Infraestructura",links:[["Estado del servidor","/admin/system","server"],["Mantenimiento","/admin/maintenance","power"],["Limpieza de caché","/admin/cleanup","refresh"],["API V1 y retiro","/admin/api-v1","clock"],["API V2","/admin/api-v2","shield"],["Google Play","/admin/play","phone"]]},
 {label:"Servicios",links:[["Proveedores VPN","/admin/providers","layers"],["Exportaciones","/admin/exports","file"],["Catálogo VPN","/admin/catalog","refresh"],["Notificaciones","/admin/notifications","bell"],["Tienda y pagos","/admin/store","file"],["Mensajes de soporte","/admin/support","message"],["Códigos de regalo","/admin/gifts","file"]]},
 {label:"Supervisión",links:[["Observabilidad","/admin/observability","activity"],["Alertas","/admin/alerts","alert"],["Rendimiento P95","/admin/performance","chart"],["Documentación","/admin/resources","book"]]}
];
function NavIcon({name}){
 const icons={
  dashboard:"M3 3h7v7H3z M14 3h7v7h-7z M3 14h7v7H3z M14 14h7v7h-7z",
  chart:"M3 3v18h18 M6 16l5-5 4 3 6-8",
  list:"M8 5h13 M8 12h13 M8 19h13 M3 5h1 M3 12h1 M3 19h1",
  search:"M10.5 3a7.5 7.5 0 1 0 0 15a7.5 7.5 0 1 0 0-15 M16 16l5 5",
  message:"M21 11.5a8.5 8.5 0 0 1-8.5 8.5H4l2-4.3A8.5 8.5 0 1 1 21 11.5z M8 10h8 M8 14h5",
  server:"M4 4h16v7H4z M4 14h16v7H4z M8 8h1 M8 18h1",
  power:"M12 2v11 M6 6a9 9 0 1 0 12 0",
  clock:"M12 3a9 9 0 1 0 0 18a9 9 0 1 0 0-18 M12 7v5l4 2",
  shield:"M12 2l9 4v6c0 5-4 9-9 10c-5-1-9-5-9-10V6z M9 12l2 2 4-4",
  phone:"M6 2h12v20H6z M10 18h4",
  layers:"M12 2l9 5-9 5-9-5z M3 12l9 5 9-5 M3 17l9 5 9-5",
  file:"M6 2h8l5 5v15H6z M14 2v5h5 M9 12h7 M9 17h7",
  refresh:"M20 8a8 8 0 0 0-14-3L3 8 M3 3v5h5 M4 16a8 8 0 0 0 14 3l3-3 M21 21v-5h-5",
  bell:"M18 8a6 6 0 0 0-12 0c0 8-3 8-3 10h18c0-2-3-2-3-10 M10 22h4",
  activity:"M2 12h5l3-8 4 16 3-8h5",
  alert:"M12 2l10 19H2z M12 9v5 M12 18h.01",
  book:"M12 5c-3-2-6-2-10-1v16c4-1 7-1 10 1c3-2 6-2 10-1V4c-4-1-7-1-10 1z M12 5v16"
 };
 return <svg className="sp-admin-nav-icon" width="20" height="20" viewBox="0 0 24 24"
  fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round"
  strokeLinejoin="round" aria-hidden="true"><path d={icons[name]||icons.dashboard}/></svg>;
}
export default function AdminNav({children}){
 const pathname=usePathname(),[expanded,setExpanded]=useState(false);
 useEffect(()=>{setExpanded(window.matchMedia("(min-width: 980px)").matches);},[]);
 useEffect(()=>{const onKey=e=>{if(e.key==="Escape")setExpanded(false);};window.addEventListener("keydown",onKey);return()=>window.removeEventListener("keydown",onKey);},[]);
 if(pathname==="/admin/login")return children;
 const name=groups.flatMap(g=>g.links).find(item=>item[1]===pathname)?.[0]||"Panel";
 return <div className="sp-admin-shell" data-expanded={expanded?"true":"false"}>
  <div className="sp-admin-toolbar">
   <button type="button" className="sp-admin-hamburger" aria-controls="sp-admin-sidebar"
    aria-expanded={expanded} aria-label={expanded?"Cerrar menú lateral":"Abrir menú lateral"}
    onClick={()=>setExpanded(x=>!x)}><span/><span/><span/></button>
   <strong>{name}</strong><small>SP-DECODE · Administración Cloud</small>
  </div>
  {expanded&&<button className="sp-admin-menu-backdrop" type="button" aria-label="Cerrar menú" onClick={()=>setExpanded(false)}/>}
  <aside id="sp-admin-sidebar" className="sp-admin-sidebar" aria-label="Menú lateral de administración" aria-hidden={!expanded} inert={!expanded}>
   <div className="sp-admin-sidebar-brand"><img src="/icon.svg" width="36" height="36" alt=""/><div><strong>SP-DECODE</strong><span>Centro de administración</span></div></div>
   <nav className="sp-admin-sidebar-scroll" aria-label="Secciones administrativas">
    {groups.map(group=><section key={group.label} className="sp-admin-nav-group">
      <h2>{group.label}</h2>
      {group.links.map(([label,url,icon])=><Link key={url} href={url} aria-current={pathname===url?"page":undefined}
       className={pathname===url?"current":""} onClick={()=>{if(window.innerWidth<980)setExpanded(false);}}>
       <NavIcon name={icon}/><span>{label}</span></Link>)}
    </section>)}
   </nav>
  </aside>
  <div className="sp-admin-content">{children}</div>
 </div>;
}
