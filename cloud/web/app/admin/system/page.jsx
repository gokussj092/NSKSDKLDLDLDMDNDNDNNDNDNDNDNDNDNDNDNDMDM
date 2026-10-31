import AdminDashboard from "../admin-dashboard.jsx";
export const metadata={title:"Estado de infraestructura",robots:{index:false,follow:false}};
export default function SystemPage(){return <main id="main" className="admin-wrap admin-wide">
 <span className="section-kicker">Administración · Infraestructura</span>
 <h1 className="admin-title">Estado del servidor</h1>
 <p className="muted">Salud del servidor y control de mantenimiento global. Cada función de administración dispone de su propia página.</p>
 <AdminDashboard mode="infrastructure"/>
</main>;}
