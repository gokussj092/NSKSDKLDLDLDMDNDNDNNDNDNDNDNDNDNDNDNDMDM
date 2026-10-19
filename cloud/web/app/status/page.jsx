import Link from "next/link";
import PublicStatus from "./public-status.jsx";
export const metadata={title:"Estado del servicio",description:"Estado público y disponibilidad de SP-DECODE Cloud."};
export default function Status(){
  return <main id="main" className="shell page-wrap"><span className="section-kicker">Disponibilidad</span>
    <h1 className="page-title">Estado del servicio</h1><p className="page-lead">Información general sin detalles internos ni datos de usuarios. El proyecto permanece en etapa de validación.</p>
    <PublicStatus/>
    <div className="feature-grid two status-cards">
      <article className="feature-card"><div className="feature-index">API</div><h2>Acceso Android</h2><p>Requiere sesiones autenticadas, disponibilidad del servidor y verificación Play Integrity real antes de su publicación.</p></article>
      <article className="feature-card"><div className="feature-index">BUILD</div><h2>Aplicación Cloud</h2><p>El APK de producción no ha sido lanzado como parte de estas fases. No se ofrece un enlace de instalación todavía.</p></article>
    </div><p><Link className="button subtle" href="/docs">Información técnica</Link></p>
  </main>;
}
