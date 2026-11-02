import AdminFeedback from "../admin-feedback.jsx";
export const metadata={title:"Solicitudes de usuarios · SP-DECODE",robots:{index:false,follow:false}};
export default function Page(){return <main id="main" className="admin-wrap admin-wide">
 <span className="section-kicker">SP-DECODE · Administración</span>
 <h1 className="admin-title">Solicitudes de usuarios</h1>
 <p className="muted">Nuevos métodos APK, reportes de errores y sugerencias.</p>
 <AdminFeedback/>
</main>;}
