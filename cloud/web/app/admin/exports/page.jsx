import AdminDashboard from "../admin-dashboard.jsx";
export const metadata={title:"Exportaciones compatibles",robots:{index:false,follow:false}};
export default function Page(){return <main id="main" className="admin-wrap admin-wide">
 <span className="section-kicker">SP-DECODE · Administración</span>
 <h1 className="admin-title">Exportaciones compatibles</h1>
 <p className="muted">Política de exportaciones Unlocked y compatibilidad.</p>
 <AdminDashboard mode="exports"/>
</main>;}
