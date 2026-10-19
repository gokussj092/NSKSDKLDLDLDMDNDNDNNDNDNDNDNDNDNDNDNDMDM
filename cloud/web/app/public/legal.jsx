"use client";
import Link from "next/link";
import {usePublicLocale} from "./site-chrome.jsx";
/*
 * This is the same provisional policy and Terms substance as the C8 website,
 * translated for visitors. Never silently represent either document as final.
 */
const docs={
 es:{
 terms:{label:"Información legal",title:"Términos y condiciones de SP-DECODE",
  intro:"Versión del documento: 18 de octubre de 2026. Borrador de desarrollo sujeto a revisión legal antes de la publicación pública.",
  notice:"Pendiente para producción: identidad legal y domicilio del responsable, derechos del consumidor, jurisdicción, mecanismos de reclamación y revisión de las políticas de proveedores y marcas. Este borrador no es un documento legal definitivo.",
  sections:[
  ["1. Servicio","SP-DECODE es una aplicación Android que envía configuraciones seleccionadas expresamente por la persona usuaria a un servicio remoto para interpretar formatos de configuración de aplicaciones VPN. No ofrece una conexión VPN ni garantiza que un perfil funcione en un proveedor externo."],
  ["2. Uso autorizado","Procesa únicamente configuraciones propias o aquellas para las que tengas permiso. No se permite utilizar SP-DECODE para acceder sin autorización a servicios, cuentas o información de terceros, evadir restricciones de acceso o infringir derechos."],
  ["3. Datos y descifrado","Los archivos pueden contener contraseñas, hosts, tokens y otros datos sensibles. Al solicitar un descifrado autorizas el envío del archivo o texto al servidor de SP-DECODE para su procesamiento. Las consultas a proveedores externos se limitan a integraciones previstas y se describen en la política de privacidad."],
  ["4. Disponibilidad y limitaciones","La compatibilidad depende de la versión y el formato. El servicio puede generar errores, devolver resultados no compatibles o interrumpirse por mantenimiento o servicios externos. No se garantiza disponibilidad continua ni compatibilidad con todas las aplicaciones VPN."],
  ["5. Aplicaciones de terceros","Los nombres e iconos de aplicaciones externas identifican formatos. No implican patrocinio, afiliación ni autorización de las personas titulares de esas marcas. Las atribuciones y permisos de los recursos gráficos deben revisarse antes de su distribución comercial."],
  ["6. Responsabilidades","Cada persona debe verificar los resultados y proteger las credenciales exportadas. Estas condiciones no limitan derechos irrenunciables establecidos en la legislación aplicable ni excluyen responsabilidades que legalmente no pueden excluirse."],
  ["7. Aceptación y retirada","Antes del primer procesamiento Cloud se solicita aceptar expresamente estos términos y la política de privacidad. Puedes consultarlos y retirar el consentimiento desde Ajustes. Al retirarlo se bloquean nuevas solicitudes sin borrar automáticamente el historial cifrado local. Los cambios sustanciales deberán requerir una nueva aceptación cuando corresponda."],
  ["8. Cambios y contacto","Los cambios sustanciales de estas condiciones requerirán actualizar el documento y solicitar nuevo consentimiento cuando corresponda. Para soporte escribe a soporte@spdecode.xyz."]
 ]},
 privacy:{label:"Privacidad",title:"Privacidad y tratamiento de datos",
  intro:"Versión del borrador: 18 de octubre de 2026. Documento informativo provisional sujeto a revisión legal antes del lanzamiento público.",
  notice:"Antes de publicar la aplicación deben completarse la identidad legal del responsable, jurisdicción, datos de contacto, políticas de proveedores, bases del tratamiento, plazos concretos de metadatos, derechos y procedimientos de eliminación. Esta página no reemplaza el aviso legal definitivo.",
  sections:[
  ["Qué recibe el servidor","Cuando solicitas un descifrado desde Android, se envía el archivo o texto cifrado. Algunos formatos requieren contraseña o HWID que introduces expresamente. Las importaciones externas consultan proveedores permitidos y pueden compartir una referencia de configuración con esos proveedores."],
  ["Cómo se procesa","La aplicación transmite los datos mediante HTTPS para procesarlos en servicios privados. Se aplican límites de tamaño y tiempo y se utilizan archivos temporales que se eliminan al terminar. El servicio no mantiene almacenamiento persistente de los archivos o resultados descifrados."],
  ["Autenticación y prevención del abuso","Se emplean verificaciones temporales de integridad de la aplicación, sesiones breves y controles para limitar solicitudes. Pueden procesarse direcciones IP mediante identificadores hash para prevenir abusos. La administración solo consulta métricas agregadas, no el contenido de los archivos."],
  ["Historial y resultados en Android","Los resultados se muestran en la aplicación y el historial se guarda localmente de acuerdo con la configuración del dispositivo. La web no ofrece un historial remoto ni un visor de archivos subidos."],
  ["Catálogos y caché local","La aplicación puede comprobar actualizaciones del catálogo como máximo una vez cada 24 horas durante el uso, siempre que exista consentimiento. Sus iconos y datos se protegen en almacenamiento privado mediante AES-256-GCM y Android Keystore, sin copias de seguridad de la aplicación. La caché funciona sin conexión; el procesamiento de configuraciones necesita el servidor."],
  ["Consentimiento y retirada","Antes del primer uso se muestran los documentos legales y se solicita aceptación explícita. La versión y fecha se registran cifradas en el dispositivo. Desde Ajustes puedes volver a consultarlos y retirar el consentimiento para bloquear nuevas solicitudes. No se eliminan automáticamente los resultados que ya tengas guardados."],
  ["Protección y límites","El cifrado de datos locales protege frente a la lectura o modificación casual, pero no evita que un dispositivo comprometido vea información mientras se usa la aplicación. Los resultados exportados fuera de la aplicación quedan bajo responsabilidad de quien los recibe."],
  ["Estado de la política","Esta política es provisional y debe completarse con información legal sobre la entidad responsable, conservación de metadatos, derechos de usuarios y procedimientos de solicitudes antes de su publicación definitiva."],
  ["Contacto de soporte","Para consultas generales puedes escribir a soporte@spdecode.xyz. El procedimiento formal para solicitudes de privacidad y datos personales se definirá en el aviso definitivo."]
 ]},
 support:{label:"Soporte",title:"¿Necesitas ayuda con SP-DECODE?",
  intro:"Encuentra orientación sobre la aplicación y los canales de contacto oficiales.",
  notice:"Evita compartir contraseñas, tokens, claves o configuraciones privadas en mensajes de soporte. Nunca solicitaremos tus credenciales personales para una consulta general.",
  sections:[
  ["Ayuda con archivos","Si un archivo no se reconoce, confirma su extensión y la versión de la aplicación que lo exportó. Algunos formatos requieren datos adicionales o pueden dejar de ser compatibles tras una actualización del proveedor."],
  ["Problemas de conexión","Comprueba la conexión a Internet y vuelve a intentar la operación. Si el servicio está en mantenimiento, puede que algunas funciones estén temporalmente indisponibles."],
  ["Historial y privacidad","Puedes administrar o eliminar el historial desde la aplicación. Para conocer cómo se procesan los archivos, consulta la política de privacidad y los términos de uso."],
  ["Contacto","Para informar de un problema, incluye la versión de SP-DECODE, el modelo de Android y una descripción del error sin adjuntar datos confidenciales."]
 ]}
 },
 en:{
 terms:{label:"Legal information",title:"SP-DECODE Terms and Conditions",
  intro:"Document version: October 18, 2026. Development draft subject to legal review before public release.",
  notice:"Required before production: legal identity and address of the responsible entity, consumer rights, jurisdiction, complaint procedures and review of third-party provider and trademark policies. This draft is not a final legal agreement.",
  sections:[
  ["1. Service","SP-DECODE is an Android application that transmits configurations explicitly selected by the user to a remote service in order to interpret VPN app configuration formats. It does not provide a VPN connection or guarantee that any profile will function with an external provider."],
  ["2. Authorized use","Only process configurations you own or are permitted to handle. SP-DECODE must not be used to access third-party services, accounts or information without authorization, bypass access restrictions or violate rights."],
  ["3. Data and decoding","Files may contain passwords, hosts, tokens and other sensitive data. By requesting decoding you authorize transmission of that file or text to SP-DECODE's server for processing. Requests to external providers are limited to intended integrations and described in the privacy policy."],
  ["4. Availability and limitations","Compatibility depends on format and exporter version. The service may return errors or incompatible results, or be interrupted for maintenance or external dependencies. Continuous uptime and compatibility with every VPN application are not guaranteed."],
  ["5. Third-party applications","Names and icons of other applications are used to identify formats. They do not imply sponsorship, affiliation or authorization from trademark owners. Attribution and permission for graphic resources must be reviewed before commercial distribution."],
  ["6. Responsibilities","Users must verify results and protect exported credentials. These conditions do not limit mandatory rights under applicable law or exclude liabilities that cannot lawfully be excluded."],
  ["7. Acceptance and withdrawal","Before the first Cloud operation, express acceptance of these terms and the privacy policy is requested. You can review them and withdraw consent in Settings. Withdrawal prevents new requests without automatically deleting encrypted local history. Material changes will require renewed acceptance when applicable."],
  ["8. Changes and contact","Material changes require an updated document and renewed consent when appropriate. For support, email soporte@spdecode.xyz."]
 ]},
 privacy:{label:"Privacy",title:"Privacy and data processing",
  intro:"Draft version: October 18, 2026. Provisional information document requiring legal review before public release.",
  notice:"Before release, the legal controller identity, jurisdiction, contact details, provider policies, legal bases, specific metadata retention periods, user rights and deletion procedures must be completed. This page is not a substitute for a final privacy notice.",
  sections:[
  ["What the server receives","When you expressly request decoding in Android, the encrypted file or text is transmitted. Some formats require a password or HWID you provide. External imports contact authorized providers and may share a configuration reference with those providers."],
  ["How data is processed","Data is transferred via HTTPS and processed by private services. Size and time limits apply, and temporary files are deleted when processing finishes. The service does not persistently store uploaded files or decoded results."],
  ["Authentication and abuse prevention","Temporary application integrity checks, short-lived sessions and request limiting are used. IP addresses may be represented as hashes for anti-abuse purposes. Administration views aggregate metrics, not file contents."],
  ["History and results on Android","Results are shown in the Android application, where history is saved locally according to the device's settings. This website does not provide remote history or a viewer for uploaded files."],
  ["Catalogs and local storage","While in use and with consent, the application may check for catalog updates at most once every 24 hours. Catalog icons and data are protected in private storage with AES-256-GCM and Android Keystore; application backups are disabled. Cached data remains available offline, but decoding needs the server."],
  ["Consent and withdrawal","Before the first Cloud use, legal documents are displayed and explicit consent is requested. The version and acceptance date are encrypted on the device. Settings allow you to review the documents and withdraw consent, blocking new requests. Previously saved local results are not automatically deleted."],
  ["Security and limitations","Local encryption protects against casual inspection or tampering but cannot prevent a compromised device from accessing information while in use. Results exported outside the application are controlled by the recipient."],
  ["Policy status","This policy remains provisional and must be completed with the controller's legal information, metadata retention rules, user rights and request handling procedures before formal publication."],
  ["Support contact","For general inquiries, email soporte@spdecode.xyz. A formal process for privacy and personal-data requests will be established in the final notice."]
 ]},
 support:{label:"Support",title:"Need help with SP-DECODE?",
  intro:"Find help for the Android application and official contact channels.",
  notice:"Do not send passwords, tokens, keys or private configurations in support messages. We will never ask for your personal credentials for a general support inquiry.",
  sections:[
  ["File assistance","If a file is not recognized, check its extension and the version of the exporting application. Some formats require extra information or may become incompatible when a provider changes its export method."],
  ["Connection issues","Check your Internet connection and retry. Some features may be temporarily unavailable during service maintenance."],
  ["History and privacy","You can manage or delete saved history in the app. Refer to the privacy policy and terms for information about data processing."],
  ["Contact","To report a problem, describe your SP-DECODE version, Android device and the error, without attaching confidential data."]
 ]}
 }};
export default function PublicLegal({kind}){
 const {lang}=usePublicLocale();const d=docs[lang][kind];
 return <main id="main" className="sp-public-main"><article className="sp-container sp-legal">
  <span className="sp-kicker">{d.label}</span><h1>{d.title}</h1><p className="sp-legal-lead">{d.intro}</p>
  {d.sections.map(([title,body],i)=><section key={i} className="sp-legal-card"><h2>{title}</h2><p>{body}</p></section>)}
  {kind==="support"&&<a className="sp-support-email" href="mailto:soporte@spdecode.xyz">soporte@spdecode.xyz ↗</a>}
  <div className="sp-legal-notice" role="note">{d.notice}</div>
  <div className="sp-cta-links" style={{marginTop:28}}><Link href="/privacy">{lang==="es"?"Privacidad":"Privacy"}</Link><Link href="/terms">{lang==="es"?"Términos":"Terms"}</Link><Link href="/support">{lang==="es"?"Soporte":"Support"}</Link></div>
 </article></main>;
}
