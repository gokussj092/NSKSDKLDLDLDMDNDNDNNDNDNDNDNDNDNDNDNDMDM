import AdminReport from "../admin-report.jsx";
export const metadata={title:"Analítica operativa",robots:{index:false,follow:false}};
export default function AnalyticsPage(){return <main id="main" className="admin-wrap admin-wide">
 <span className="section-kicker">Administración · Telemetría</span>
 <h1 className="admin-title">Actividad y rendimiento</h1>
 <p className="muted">Estadísticas agregadas, filtros y tendencias por periodo.</p>
 <AdminReport view="analytics"/>
</main>;}
