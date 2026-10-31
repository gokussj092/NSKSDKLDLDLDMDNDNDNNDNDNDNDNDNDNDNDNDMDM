import AdminDashboard from "../admin-dashboard.jsx";
export const metadata={title:"API V1 · Retiro programado",robots:{index:false,follow:false}};
export default function Page(){return <main id="main" className="admin-wrap admin-wide">
 <span className="section-kicker">SP-DECODE · Administración</span>
 <h1 className="admin-title">API V1 · Retiro programado</h1>
 <p className="muted">Programa la desactivación a 48 horas y administra los controles de V1.</p>
 <AdminDashboard mode="api-v1"/>
</main>;}
