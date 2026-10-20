import AdminReport from "../admin-report.jsx";
export const metadata={title:"Incidencias por motor",robots:{index:false,follow:false}};
export default function ReportsPage(){return <main id="main" className="admin-wrap admin-wide">
 <span className="section-kicker">Administración · Incidencias</span>
 <h1 className="admin-title">Diagnóstico de descifradores</h1>
 <p className="muted">Fallos automáticos por formato y proveedor VPN. Solo códigos técnicos y contadores: no se guardan archivos ni claves.</p>
 <AdminReport view="reports"/>
</main>;}
