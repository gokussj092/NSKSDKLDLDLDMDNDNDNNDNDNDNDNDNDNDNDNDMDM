import AdminDashboard from "./admin-dashboard.jsx";
export const metadata={title:"Panel de operaciones",robots:{index:false,follow:false}};
export default function AdminPage(){return <main id="main" className="admin-wrap">
  <span className="section-kicker">Operaciones privadas</span>
  <h1 className="admin-title">Centro de control</h1>
  <p className="muted">Monitoreo agregado y mantenimiento del servidor. El panel no almacena ni muestra configuraciones descifradas.</p>
  <AdminDashboard/>
</main>}
