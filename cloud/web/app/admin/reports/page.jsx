import AdminReport from "../admin-report.jsx";
export const metadata={title:"Incidencias por motor",robots:{index:false,follow:false}};
export default function ReportsPage(){return <main id="main" className="admin-wrap admin-wide">
 <span className="section-kicker">Administración · Incidencias</span>
 <h1 className="admin-title">Incidencias</h1>
 <p className="muted">Registros de errores y métricas de fallos. Los diagnósticos detallados están en su propia página.</p>
 <AdminReport view="reports"/>
</main>;}
