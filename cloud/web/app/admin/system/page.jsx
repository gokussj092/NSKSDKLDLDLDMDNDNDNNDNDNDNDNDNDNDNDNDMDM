import AdminDashboard from "../admin-dashboard.jsx";
import AdminObservability from "../admin-observability.jsx";
import AdminCatalogPush from "../admin-catalog-push.jsx";
import Link from "next/link";
export const metadata={title:"Infraestructura y mantenimiento",robots:{index:false,follow:false}};
export default function SystemPage(){return <main id="main" className="admin-wrap admin-wide">
  <span className="section-kicker">Administración · Infraestructura</span>
  <h1 className="admin-title">Servicios y mantenimiento</h1>
  <p className="muted">Configura proveedores, controla el mantenimiento y consulta el estado real de la infraestructura. Los gráficos de uso permanecen en Analítica.</p>
  <AdminDashboard mode="system"/>
  <AdminObservability mode="system"/>
  <AdminCatalogPush/>
  <section className="admin-card sp-admin-legal-links" aria-labelledby="sp-admin-legal-title">
   <div className="sp-admin-section-heading"><div>
    <h2 id="sp-admin-legal-title">Documentación y soporte</h2>
    <p className="muted">Accesos a los mismos documentos oficiales que ve el público, con el diseño bilingüe de la web. No se mantienen versiones separadas para el panel.</p>
   </div></div>
   <nav className="sp-admin-legal-grid" aria-label="Documentos y canales oficiales">
    <Link href="/privacy"><strong>Política de privacidad</strong><span>Permisos, tratamiento y conservación de datos</span></Link>
    <Link href="/terms"><strong>Términos y condiciones</strong><span>Condiciones actuales del servicio SP-DECODE</span></Link>
    <Link href="/support"><strong>Soporte técnico</strong><span>Contacto y procedimientos de ayuda</span></Link>
   </nav>
  </section>
</main>;}
