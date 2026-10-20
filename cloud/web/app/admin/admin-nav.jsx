"use client";
import Link from "next/link";
import {usePathname} from "next/navigation";
const routes=[["Resumen","/admin","dashboard"],["Analítica","/admin/analytics","analytics"],["Incidencias","/admin/reports","issues"],["Servicios","/admin/system","services"]];
function NavIcon({type}){
 const nodes={
  dashboard:<><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></>,
  analytics:<><path d="M3 3v18h18"/><path d="m6 16 5-5 4 3 6-8"/></>,
  issues:<><path d="M9 3h6l1 3h4v15H4V6h4z"/><path d="M8 12h8M8 16h5"/></>,
  services:<><path d="M4 7h16M4 17h16"/><circle cx="9" cy="7" r="3"/><circle cx="15" cy="17" r="3"/></>,
 };
 return <svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">{nodes[type]}</svg>;
}
export default function AdminNav(){
 const pathname=usePathname();
 if(pathname==="/admin/login")return null;
 return <nav className="admin-navigation" aria-label="Secciones administrativas">
  {routes.map(([name,url,icon])=><Link key={url} href={url}
   aria-current={pathname===url?"page":undefined} className={pathname===url?"current":""}>
   <NavIcon type={icon}/><span>{name}</span>
  </Link>)}
 </nav>;
}
