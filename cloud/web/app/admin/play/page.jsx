import AdminDashboard from "../admin-dashboard.jsx";
export const metadata={title:"Google Play y beta",robots:{index:false,follow:false}};
export default function Page(){return <main id="main" className="admin-wrap admin-wide">
 <span className="section-kicker">SP-DECODE · Administración</span>
 <h1 className="admin-title">Google Play y beta</h1>
 <p className="muted">Configuración de admisión de testers y Play Integrity.</p>
 <AdminDashboard mode="play"/>
</main>;}
