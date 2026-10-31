"use client";
import Link from "next/link";
import {usePathname} from "next/navigation";
import {useEffect,useState} from "react";
export const groups=[
 {label:"General",links:[["Resumen","/admin","◫"],["Analítica","/admin/analytics","▥"],["Incidencias","/admin/reports","≡"],["Diagnóstico","/admin/diagnostics","⌕"]]},
 {label:"Infraestructura",links:[["Estado del servidor","/admin/system","▤"],["Mantenimiento","/admin/maintenance","◉"],["API V1 y retiro","/admin/api-v1","◷"],["API V2","/admin/api-v2","⬡"],["Google Play","/admin/play","▯"]]},
 {label:"Servicios",links:[["Proveedores VPN","/admin/providers","◈"],["Exportaciones","/admin/exports","▧"],["Catálogo VPN","/admin/catalog","⟳"],["Notificaciones","/admin/notifications","♧"]]},
 {label:"Supervisión",links:[["Observabilidad","/admin/observability","⌁"],["Alertas","/admin/alerts","!"],["Rendimiento P95","/admin/performance","▥"],["Documentación","/admin/resources","▣"]]}
];
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
   <div className="sp-admin-sidebar-brand"><strong>SP-DECODE</strong><span>Centro de administración</span></div>
   <nav className="sp-admin-sidebar-scroll" aria-label="Secciones administrativas">
    {groups.map(group=><section key={group.label} className="sp-admin-nav-group">
      <h2>{group.label}</h2>
      {group.links.map(([label,url,icon])=><Link key={url} href={url} aria-current={pathname===url?"page":undefined}
       className={pathname===url?"current":""} onClick={()=>{if(window.innerWidth<980)setExpanded(false);}}>
       <span className="sp-admin-nav-icon" aria-hidden="true">{icon}</span><span>{label}</span></Link>)}
    </section>)}
   </nav>
  </aside>
  <div className="sp-admin-content">{children}</div>
 </div>;
}
