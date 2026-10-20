import AdminDashboard from "./admin-dashboard.jsx";
import AdminReport from "./admin-report.jsx";
export const metadata={title:"Centro de control",robots:{index:false,follow:false}};
export default function AdminPage(){return <main id="main" className="admin-wrap admin-wide">
 <span className="section-kicker">SP-DECODE · Administración</span>
 <h1 className="admin-title">Centro de control</h1>
 <p className="muted">Operaciones y estado de servicios. Estadísticas reales, anónimas y posteriores al despliegue.</p>
 <AdminDashboard/>
 <AdminReport view="overview"/>
</main>;}
