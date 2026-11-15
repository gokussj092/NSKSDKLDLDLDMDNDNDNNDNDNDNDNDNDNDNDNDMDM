# SP-DECODE — Anexo propuesto a Términos y Aviso de Privacidad para Fase 7

**ESTADO: BORRADOR PARA REVISIÓN, NO PUBLICADO, NO FUNCIONES HABILITADAS.** El sitio público `/terms` y `/privacy` sigue describiendo exclusivamente las funciones hoy activas. Publicar este anexo **solamente después** de implementar el login, el servicio de análisis y los respaldos, confirmar quién es el responsable legal del servicio y revisar la legislación aplicable.

## 1. Términos — adiciones propuestas

**Cuenta opcional.** SP-DECODE permite utilizar sus funciones gratuitas sin crear cuenta. Para compras de créditos, análisis de APK, soporte asociado al caso e historial comercial se requiere una cuenta identificada mediante Google o correo verificado y contraseña. El nombre público es único pero editable conforme a reglas de disponibilidad; el usuario conserva un identificador interno permanente.

**Seguridad de credenciales.** La persona titular debe proteger sus medios de acceso y reportar posibles usos no autorizados. SP-DECODE aplica límites de intentos, notificaciones y medidas técnicas para reducir abuso; no garantiza protección absoluta ante servicios externos o dispositivos comprometidos. El cambio de contraseña revoca las sesiones pertinentes.

**APK enviado con autorización.** Solo podrán remitirse APK/APKS de los que el titular tenga derecho de análisis. SP-DECODE no ejecutará automáticamente código del APK en su infraestructura productiva y limitará herramientas según políticas de sandbox, privacidad, licencias y autorización. Los resultados pueden ser incompletos si intervienen autenticación, claves, protección antiabuso o restricciones legales. El cliente debe consentir de manera separada si el caso se enviará a revisión humana o a un proveedor externo de IA. Nunca prometer acceso o descifrado garantizado.

**Créditos y compras.** El precio, impuesto y moneda aplicables deben mostrarse antes de confirmar una compra y con la pasarela permitida por el canal de distribución. No descontar crédito si el trabajo falla sin entregar el resultado contratado; los reintentos técnicos no causan cobro duplicado. Diferenciar liberación de crédito de un reembolso monetario: este se rige por las condiciones de Google Play cuando corresponda y por derechos legales; no establecer una exclusión absoluta de reembolsos.

**Disponibilidad y suspensión.** Es posible que un proveedor VPN cambie su protocolo, que un análisis requiera asistencia o que el servidor esté temporalmente fuera de línea. Informar interrupciones significativas sin prometer disponibilidad ininterrumpida. Se podrá limitar abuso o fraude con revisión.

**Soporte.** La entrega humana tendrá trazabilidad y control de acceso, con enlaces temporales y eliminación posterior. No solicitar contraseñas del correo, claves privadas ni credenciales de otros servicios por correo ordinario.

**Modificaciones.** Las condiciones y tarifas pueden cambiar hacia delante, con aviso y aceptación renovada cuando se introduzcan cambios sustanciales. No modificar unilateralmente compras ya realizadas contrariamente a la ley.

## 2. Aviso de privacidad — adiciones propuestas

**Datos previstos.** Correo verificado, identificador interno, username, nombre visible, identidades OAuth vinculadas, fecha de aceptación de condiciones, registro de eventos de seguridad, hashes de contraseña (con salt), tokens de sesión derivados y revocables, solicitudes de recuperación; datos de compras, créditos, trabajos APK, resultados/entregas y soporte cuando las funciones estén activas. **Nunca se almacena la contraseña en texto plano.**

**Finalidades primarias.** Verificación de identidad, creación y seguridad de cuenta, comunicación de alertas, restauración del acceso, contabilidad de compras y créditos, procesamiento de APK autorizado, entrega de informes y atención de soporte.

**Finalidades opcionales.** Comunicaciones promocionales y cualquier uso por IA externa no imprescindible requieren aviso y consentimiento separados donde corresponda. No presumir que aceptar un correo de seguridad implica consentimiento de marketing.

**Destinatarios y almacenamiento.** La operación principal se realiza en infraestructura contratada por SP-DECODE. Podrían almacenarse copias **cifradas del lado del VPS** en un proveedor externo como Supabase, según región y configuración finalmente seleccionadas. Solo se subirán objetos cifrados con una clave de recuperación que no se conserva en el proveedor de destino. La copia de base de datos podrá contener hashes de contraseñas y datos de clientes; siguen siendo **datos personales** y deben protegerse con controles de acceso, contratos y retención.

**Conservación.** Definir y publicar plazos diferenciados para OTP (por ejemplo 10 minutos), sesiones, eventos de seguridad, registros de cuenta, órdenes, datos fiscales, APK e informes, casos de soporte y snapshots de recuperación, considerando obligaciones legales. La eliminación de cuenta no debe borrar de forma ilícita registros que haya obligación de conservar; sí deben anonimizarse o restringirse cuando proceda. Los respaldos cifrados seguirán sus ciclos de retención y no se utilizarán para recuperar información eliminada indebidamente.

**Acceso, rectificación, cancelación y oposición.** Proporcionar procedimiento verificable para derechos ARCO, descargar información, desvincular identidades, actualizar correo con revalidación y solicitar eliminación de cuenta desde Android y web. La identidad se verifica antes de entregar datos.

**Seguridad y avisos.** Emails de verificación, recuperación y login inusual se envían por proveedor transaccional autenticado SPF/DKIM/DMARC, sin adjuntos de configuración, contraseñas o informes privados. La bandeja administrativa (si se activa) usa acceso exclusivo de administrador con MFA, auditoría, sanitización de HTML y sin mostrar credenciales a navegador.

**Responsable y jurisdicción.** Deben incluirse la denominación legal real, domicilio/medios de contacto exigibles, responsable del tratamiento, jurisdicción, mecanismos de reclamación y base legal para transferencias y encargados. El dominio `spdecode.xyz` no sustituye la identificación formal. Verificar cumplimiento de la Ley Federal de Protección de Datos Personales en Posesión de los Particulares vigente y de protección al consumidor.

## 3. Pruebas legales antes de publicar

- Concordancia entre lo que dicen los términos, el flujo Google/correo, el código y la ficha **Data Safety** de Google Play.
- Aceptación versionada y opt-in explícito a análisis APK, revisión humana y uso de IA de terceros.
- Auditoría de eliminación/exportación de cuentas y límites de retención.
- Identidad comercial verificable, precios y política de reembolsos de Google Play, cambios de tarifa y CFDI cuando proceda.
- Traducción ES/EN y revisión jurídica humana antes de sustituir textos de `cloud/web/app/public/legal.jsx`.

**Fuentes oficiales:** Ley Federal de Protección de Datos Personales en Posesión de los Particulares (Cámara de Diputados) https://www.diputados.gob.mx/LeyesBiblio/pdf/LFPDPPP.pdf y PROFECO https://distintivodigital.profeco.gob.mx/info-codigo-de-etica.php .
