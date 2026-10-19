import "./globals.css";
import Link from "next/link";
export const metadata={
  ...(process.env.CLOUD_SITE_PUBLIC_ORIGIN?.startsWith("https://") ?
    {metadataBase:new URL(process.env.CLOUD_SITE_PUBLIC_ORIGIN)} :
    {metadataBase:new URL("https://spdecode.xyz")}),
  title:{default:"SP-DECODE Cloud | Ghost Developer",template:"%s | SP-DECODE Cloud"},
  description:"Plataforma de descifrado remoto para Android. Consulta las funciones, la arquitectura, el estado del proyecto y la política de privacidad.",
  applicationName:"SP-DECODE Cloud",
  robots:{index:process.env.CLOUD_PUBLIC_SITE_INDEX==="true",follow:process.env.CLOUD_PUBLIC_SITE_INDEX==="true"},
  openGraph:{type:"website",locale:"es_MX",siteName:"SP-DECODE Cloud",
    title:"SP-DECODE Cloud",description:"La próxima arquitectura online de SP-DECODE para Android."},
};
const links=[["Inicio","/"],["Funciones","/features"],["Documentación","/docs"],["Términos","/terms"],["Privacidad","/privacy"],["Estado","/status"]];
export default function RootLayout({children}){
  return <html lang="es"><body>
    <a className="skip" href="#main">Saltar al contenido</a>
    <header className="header">
      <div className="shell head-inner">
        <Link className="brand" href="/" aria-label="SP-DECODE Cloud, inicio">
          <span className="brand-mark" aria-hidden="true">SP</span>
          <span>SP-DECODE <span className="brand-secondary">Cloud</span></span>
        </Link>
        <nav className="nav" aria-label="Navegación principal">
          {links.map(([label,href])=><Link href={href} key={href}>{label}</Link>)}
        </nav>
      </div>
    </header>
    {children}
    <footer className="footer">
      <div className="shell footer-layout">
        <div><div className="footer-brand">SP-DECODE Cloud</div>
          <p>Infraestructura en desarrollo. El descifrado se ejecutará exclusivamente en el servidor.</p>
          <span className="muted">Desarrollado por Ghost Developer.</span>
          <p><a href="mailto:soporte@spdecode.xyz">soporte@spdecode.xyz</a></p></div>
        <div className="footer-links">
          <Link href="/features">Funciones</Link><Link href="/docs">Documentación</Link>
          <Link href="/terms">Términos</Link><Link href="/privacy">Privacidad</Link><Link href="/status">Estado</Link>
          <Link href="https://panel.spdecode.xyz/admin/login">Administración</Link>
        </div>
      </div>
      <div className="shell footer-last">SP-DECODE Cloud · Plataforma Android · Sin descifrado desde el navegador</div>
    </footer>
  </body></html>;
}
