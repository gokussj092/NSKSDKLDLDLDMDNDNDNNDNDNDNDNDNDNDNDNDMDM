import AdminObservability from "../admin-observability.jsx";
export const metadata={title:"Observabilidad",robots:{index:false,follow:false}};
export default function Page(){return <main id="main" className="admin-wrap admin-wide">
 <span className="section-kicker">SP-DECODE · Administración</span>
 <h1 className="admin-title">Observabilidad</h1>
 <p className="muted">Salud del host, disponibilidad, latencia y alarmas operativas.</p>
 <AdminObservability mode="system"/>
</main>;}
