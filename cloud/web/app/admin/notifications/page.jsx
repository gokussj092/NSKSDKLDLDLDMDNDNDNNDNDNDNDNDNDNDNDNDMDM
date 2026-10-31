import AdminNotifications from "../admin-notifications.jsx";
export const metadata={title:"Notificaciones",robots:{index:false,follow:false}};
export default function Page(){return <main id="main" className="admin-wrap admin-wide">
 <span className="section-kicker">SP-DECODE · Administración</span>
 <h1 className="admin-title">Notificaciones</h1>
 <p className="muted">Redacción, vista previa y publicación de mensajes en Android.</p>
 <AdminNotifications/>
</main>;}
