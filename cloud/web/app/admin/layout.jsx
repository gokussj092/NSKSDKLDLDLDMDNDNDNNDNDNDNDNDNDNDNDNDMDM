import AdminNav from "./admin-nav.jsx";
export default function AdminLayout({children}){
  return <><div className="admin-navigation-wrap"><AdminNav/></div>{children}</>;
}
