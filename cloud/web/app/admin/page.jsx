import AdminDashboard from "./admin-dashboard.jsx";
export const metadata={title:"Centro de control",robots:{index:false,follow:false}};
export default function AdminPage(){return <main id="main" className="admin-wrap admin-wide">
 <span className="section-kicker">SP-DECODE · Administración</span>
 <h1 className="admin-title">Centro de control</h1>
 <p className="muted">Vista rápida de infraestructura y operación. La analítica detallada, los diagnósticos y los controles están en sus secciones correspondientes.</p>
 <AdminDashboard mode="overview"/>
</main>;}
