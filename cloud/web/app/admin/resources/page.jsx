import Link from "next/link";
export const metadata={title:"Documentación y soporte",robots:{index:false,follow:false}};
export default function Page(){return <main id="main" className="admin-wrap admin-wide">
 <span className="section-kicker">SP-DECODE · Administración</span>
 <h1 className="admin-title">Documentación y soporte</h1>
 <p className="muted">Acceso a documentos públicos y vías de contacto oficiales.</p>
 <section className="admin-card sp-admin-legal-links">
  <h2>Enlaces oficiales</h2>
  <nav className="sp-admin-legal-grid" aria-label="Recursos oficiales">
   <Link href="/privacy"><strong>Privacidad</strong><span>Tratamiento de datos personales</span></Link>
   <Link href="/terms"><strong>Términos y condiciones</strong><span>Reglas de uso del servicio</span></Link>
   <Link href="/support"><strong>Soporte técnico</strong><span>Contacto y procedimientos</span></Link>
  </nav>
 </section>
</main>;}
