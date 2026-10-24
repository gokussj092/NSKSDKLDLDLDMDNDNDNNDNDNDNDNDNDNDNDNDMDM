import AdminNav from "./admin-nav.jsx";
import "./admin-theme.css";
export default function AdminLayout({children}){
 return <><div className="admin-navigation-wrap"><AdminNav/></div>{children}</>;
}
