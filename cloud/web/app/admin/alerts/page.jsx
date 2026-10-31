import AdminObservability from "../admin-observability.jsx";
export const metadata={title:"Alertas automáticas",robots:{index:false,follow:false}};
export default function Page(){return <main id="main" className="admin-wrap admin-wide">
 <span className="section-kicker">SP-DECODE · Supervisión</span>
 <h1 className="admin-title">Alertas automáticas</h1>
 <p className="muted">Revisa las alertas de proveedores, silencia eventos repetidos y limpia el historial de alertas.</p>
 <AdminObservability mode="alerts"/>
</main>;}
