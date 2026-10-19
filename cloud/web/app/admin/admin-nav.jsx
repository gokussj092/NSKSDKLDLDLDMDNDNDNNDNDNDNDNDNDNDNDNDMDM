"use client";
import Link from "next/link";
import {usePathname} from "next/navigation";
const routes=[["Resumen","/admin"],["Estadísticas","/admin/analytics"],
  ["Reportes de errores","/admin/reports"],["Infraestructura","/admin/system"]];
export default function AdminNav(){
  const pathname=usePathname();
  if(pathname==="/admin/login")return null;
  return <nav className="admin-navigation" aria-label="Secciones administrativas">
    {routes.map(([name,url])=><Link key={url} href={url}
      aria-current={pathname===url?"page":undefined} className={pathname===url?"current":""}>{name}</Link>)}
  </nav>;
}
