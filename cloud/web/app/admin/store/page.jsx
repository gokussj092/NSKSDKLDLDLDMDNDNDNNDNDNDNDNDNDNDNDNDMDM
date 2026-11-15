import AdminStore from '../admin-store.jsx';
export const metadata={title:'Tienda y pagos',robots:{index:false,follow:false}};
export default function Page(){return <main id="main" className="admin-wrap admin-wide"><span className="section-kicker">SP-DECODE · Comercio</span><h1 className="admin-title">Tienda y pagos</h1><p className="muted">Productos, precios comunes por moneda y reglas fiscales revisadas. Las credenciales de proveedores se mantienen exclusivamente en el VPS.</p><AdminStore/></main>;}
