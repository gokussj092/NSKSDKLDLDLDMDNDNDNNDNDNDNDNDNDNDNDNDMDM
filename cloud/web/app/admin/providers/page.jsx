import AdminDashboard from "../admin-dashboard.jsx";
export const metadata={title:"Proveedores VPN",robots:{index:false,follow:false}};
export default function Page(){return <main id="main" className="admin-wrap admin-wide">
 <span className="section-kicker">SP-DECODE · Administración</span>
 <h1 className="admin-title">Proveedores VPN</h1>
 <p className="muted">Control individual de las integraciones remotas y sus estados.</p>
 <AdminDashboard mode="providers"/>
</main>;}
