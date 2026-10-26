import AdminDashboard from "../admin-dashboard.jsx";
import AdminObservability from "../admin-observability.jsx";
import AdminCatalogPush from "../admin-catalog-push.jsx";
export const metadata={title:"Infraestructura y mantenimiento",robots:{index:false,follow:false}};
export default function SystemPage(){return <main id="main" className="admin-wrap admin-wide">
  <span className="section-kicker">Administración · Infraestructura</span>
  <h1 className="admin-title">Servicios y mantenimiento</h1>
  <p className="muted">Configura proveedores, controla el mantenimiento y consulta el estado real de la infraestructura. Los gráficos de uso permanecen en Analítica.</p>
  <AdminDashboard mode="system"/>
  <AdminObservability mode="system"/>
  <AdminCatalogPush/>
</main>;}
