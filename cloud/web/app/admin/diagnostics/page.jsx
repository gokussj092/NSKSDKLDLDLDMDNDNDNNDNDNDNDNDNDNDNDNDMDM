import AdminDiagnostics from "../admin-diagnostics.jsx";
export const metadata={title:"Diagnóstico técnico",robots:{index:false,follow:false}};
export default function Page(){return <main id="main" className="admin-wrap admin-wide">
 <span className="section-kicker">SP-DECODE · Administración</span>
 <h1 className="admin-title">Diagnóstico técnico</h1>
 <p className="muted">Revisión técnica de los errores de descifrado.</p>
 <AdminDiagnostics/>
</main>;}
