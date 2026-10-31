import AdminDashboard from "../admin-dashboard.jsx";
export const metadata={title:"Mantenimiento",robots:{index:false,follow:false}};
export default function Page(){return <main id="main" className="admin-wrap admin-wide">
 <span className="section-kicker">SP-DECODE · Administración</span>
 <h1 className="admin-title">Mantenimiento</h1>
 <p className="muted">Control individual de pausas operativas sin detener el resto de servicios.</p>
 <AdminDashboard mode="maintenance"/>
</main>;}
