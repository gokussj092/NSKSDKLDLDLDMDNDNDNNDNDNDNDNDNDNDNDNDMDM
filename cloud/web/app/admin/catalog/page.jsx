import AdminCatalogPush from "../admin-catalog-push.jsx";
export const metadata={title:"Catálogo Server VPN",robots:{index:false,follow:false}};
export default function Page(){return <main id="main" className="admin-wrap admin-wide">
 <span className="section-kicker">SP-DECODE · Administración</span>
 <h1 className="admin-title">Catálogo Server VPN</h1>
 <p className="muted">Control de anuncios y actualización del catálogo remoto.</p>
 <AdminCatalogPush/>
</main>;}
