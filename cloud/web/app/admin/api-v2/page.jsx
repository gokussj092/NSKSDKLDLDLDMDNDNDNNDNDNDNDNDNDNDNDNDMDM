import AdminDashboard from "../admin-dashboard.jsx";
export const metadata={title:"API V2 · Seguridad",robots:{index:false,follow:false}};
export default function Page(){return <main id="main" className="admin-wrap admin-wide">
 <span className="section-kicker">SP-DECODE · Administración</span>
 <h1 className="admin-title">API V2 · Seguridad</h1>
 <p className="muted">Disponibilidad de V2 y política de integridad independientes.</p>
 <AdminDashboard mode="api-v2"/>
</main>;}
