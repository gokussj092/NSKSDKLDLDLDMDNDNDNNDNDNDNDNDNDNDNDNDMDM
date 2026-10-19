import "./globals.css";
import SiteChrome from "./public/site-chrome.jsx";
export const metadata={
  ...(process.env.CLOUD_SITE_PUBLIC_ORIGIN?.startsWith("https://") ?
    {metadataBase:new URL(process.env.CLOUD_SITE_PUBLIC_ORIGIN)} :
    {metadataBase:new URL("https://spdecode.xyz")}),
  title:{default:"SP-DECODE | Ghost Developer",template:"%s | SP-DECODE"},
  description:"SP-DECODE para Android: explora configuraciones VPN, consulta tu historial y descubre funciones desde una interfaz clara y sencilla.",
  applicationName:"SP-DECODE",
  icons:{icon:[{url:"/icon.svg",type:"image/svg+xml"}],shortcut:"/icon.svg"},
  robots:{index:process.env.CLOUD_PUBLIC_SITE_INDEX==="true",follow:process.env.CLOUD_PUBLIC_SITE_INDEX==="true"},
  openGraph:{type:"website",url:"https://spdecode.xyz",locale:"es_MX",
    siteName:"SP-DECODE",title:"SP-DECODE — Android",
    description:"Explora e interpreta configuraciones VPN desde Android con una experiencia sencilla y moderna.",
    images:[{url:"/opengraph-image",width:1200,height:630,alt:"SP-DECODE — aplicación Android de Ghost Developer"}]},
  twitter:{card:"summary_large_image",title:"SP-DECODE — Android",
    description:"Descubre SP-DECODE para Android.",images:["/opengraph-image"]},
};
export default function RootLayout({children}){
  return <html lang="es"><body>
    <a className="skip" href="#main">Saltar al contenido</a>
    <SiteChrome>{children}</SiteChrome>
  </body></html>;
}
