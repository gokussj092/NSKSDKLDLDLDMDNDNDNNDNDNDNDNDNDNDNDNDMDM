import AdminObservability from "../admin-observability.jsx";
export const metadata={title:"Rendimiento y latencia P95",robots:{index:false,follow:false}};
export default function Page(){return <main id="main" className="admin-wrap admin-wide">
 <span className="section-kicker">SP-DECODE · Supervisión</span>
 <h1 className="admin-title">Rendimiento y latencia P95</h1>
 <p className="muted">Analiza tiempos, fallos de motor y comparaciones posteriores a una corrección.</p>
 <AdminObservability mode="performance"/>
</main>;}
