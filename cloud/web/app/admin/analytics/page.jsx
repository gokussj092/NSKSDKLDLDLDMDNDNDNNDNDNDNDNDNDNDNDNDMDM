import AdminReport from "../admin-report.jsx";
export const metadata={title:"Analítica operativa",robots:{index:false,follow:false}};
export default function AnalyticsPage(){return <main id="main" className="admin-wrap admin-wide">
  <span className="section-kicker">Administración · Telemetría</span>
  <h1 className="admin-title">Consumo y descifrados</h1>
  <p className="muted">Métricas reales del servidor por día y extensión. Solo registros agregados posteriores a la actualización.</p>
  <AdminReport view="analytics"/>
</main>;}
