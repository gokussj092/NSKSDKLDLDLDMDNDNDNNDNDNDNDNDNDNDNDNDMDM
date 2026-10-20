import AdminReport from "../admin-report.jsx";
import AdminDiagnostics from "../admin-diagnostics.jsx";
export const metadata={title:"Incidencias por motor",robots:{index:false,follow:false}};
export default function ReportsPage(){return <main id="main" className="admin-wrap admin-wide">
 <span className="section-kicker">Administración · Incidencias</span>
 <h1 className="admin-title">Diagnóstico de descifradores</h1>
 <p className="muted">Fallos automáticos y reportes expresos desde Android. No se guardan archivos, claves ni texto libre.</p>
 <AdminDiagnostics/>
 <AdminReport view="reports"/>
</main>;}
