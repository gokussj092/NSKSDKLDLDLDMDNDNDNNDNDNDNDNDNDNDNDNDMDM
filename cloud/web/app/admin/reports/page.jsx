import AdminReport from "../admin-report.jsx";
export const metadata={title:"Diagnóstico de motores",robots:{index:false,follow:false}};
export default function ReportsPage(){return <main id="main" className="admin-wrap admin-wide">
  <span className="section-kicker">Administración · Diagnóstico</span>
  <h1 className="admin-title">Fallos por extensión y motivo</h1>
  <p className="muted">Reportes agregados para priorizar correcciones. No se almacenan archivos, contenidos ni mensajes internos de los motores.</p>
  <AdminReport view="reports"/>
</main>;}
