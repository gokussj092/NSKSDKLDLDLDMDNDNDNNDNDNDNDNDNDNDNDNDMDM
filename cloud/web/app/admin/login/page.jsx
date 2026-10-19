import AdminLogin from "./admin-login.jsx";
export const metadata={title:"Acceso de administración",robots:{index:false,follow:false}};
export default function AdminLoginPage(){return <main id="main" className="admin-wrap">
  <section className="auth-card"><span className="section-kicker">Acceso restringido</span>
    <h1>Administración</h1><p className="muted">Acceso reservado a los operadores autorizados de SP-DECODE Cloud.</p>
    <AdminLogin/></section>
  </main>}
