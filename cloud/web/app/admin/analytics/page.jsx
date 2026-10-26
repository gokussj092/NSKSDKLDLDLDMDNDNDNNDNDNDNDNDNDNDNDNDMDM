import AdminReport from "../admin-report.jsx";
import AdminObservability from "../admin-observability.jsx";
export const metadata={title:"Analítica operativa",robots:{index:false,follow:false}};
export default function AnalyticsPage(){return <main id="main" className="admin-wrap admin-wide">
 <span className="section-kicker">Administración · Telemetría</span>
 <h1 className="admin-title">Actividad y rendimiento</h1>
 <p className="muted">Actividad por fecha, rendimiento y comparativas. Filtra los formatos y exporta únicamente estadísticas agregadas, sin archivos ni credenciales.</p>
 <AdminReport view="analytics"/>
 <AdminObservability/>
</main>;}
