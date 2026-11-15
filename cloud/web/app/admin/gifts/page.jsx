import AdminGiftCodes from '../admin-gifts.jsx';
export const metadata={title:'Códigos de regalo · SP-DECODE',robots:{index:false,follow:false}};
export default function Page(){return <main id="main" className="admin-wrap admin-wide">
  <span className="section-kicker">SP-DECODE · Administración</span>
  <h1 className="admin-title">Códigos de regalo</h1>
  <AdminGiftCodes/>
</main>;}
