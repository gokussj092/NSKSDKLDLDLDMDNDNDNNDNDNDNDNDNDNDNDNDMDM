import AdminLogin from "./admin-login.jsx";
export const metadata={title:"Acceso de administración",robots:{index:false,follow:false}};
export default function AdminLoginPage(){return <main id="main" className="admin-wrap sp-admin-login">
 <section className="auth-card sp-admin-login-card">
  <div className="sp-admin-login-logo"><img src="/icon.svg" alt="SP-DECODE" width="84" height="84"/></div>
  <span className="section-kicker">Acceso privado</span>
  <h1>Panel administrativo</h1>
  <p className="muted">Acceso reservado a operadores autorizados. Tu sesión está protegida.</p>
  <AdminLogin/>
 </section>
 </main>;}
