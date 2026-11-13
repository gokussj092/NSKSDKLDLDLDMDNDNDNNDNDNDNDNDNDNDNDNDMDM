# SP-DECODE QA: FCM en segundo plano, buzón privado, actividad y cargos

Rama: `ci/unity-ads-online-qa`. Mantener firma Android, HPKE, anuncios Unity y `main` sin modificar. Versión QA: 1.1.27 (42).

## Notificaciones sin abrir la app
- El problema identificado: FCM enviaba exclusivamente `data.noticeId` y Android programaba un Worker. Doze, límites de WorkManager y estados inactivos podían retrasar el aviso hasta que se iniciara la app.
- FCM HTTP v1 envía ahora un bloque `notification` con texto **genérico** además de un ID opaco. Android/Google Play services puede mostrarlo directamente al recibirlo en segundo plano, sin ejecutar el Worker.
- Al recibirlo en primer plano, `CloudPushService` muestra un aviso genérico mediante `NotificationManager`. El WorkManager anterior sigue como vía de reconciliación, historial y fallbacks.
- Canales: `service-notices-chime-v2` (generales) y `account-alerts-v1` (soporte, compras, seguridad). Respetar silencio, permisos, controles del usuario y consentimiento vigente; **no** reactivar notificaciones que el usuario desactivó.
- Nunca poner texto de conversación, correo, precio, token ni datos bancarios dentro de FCM. Las notificaciones de cuenta son `token`-targeted, nunca `topic`-broadcast.
- Android registra tokens FCM solo después de consentimiento y una sesión válida; el backend los cifra con AES-GCM y los vincula a una cuenta. Al cerrar sesión se solicita su desvinculación. Una respuesta fallida no concede acceso a conversaciones o compras.
- FCM no garantiza entrega después de un **forzar detención** manual, permisos denegados, batería restringida, falta de internet o restricciones del fabricante. Probar también en pantalla bloqueada, sin abrir la app, con y sin optimización de batería. No implementar un servicio permanente para eludir restricciones.

## Backend
- Aplicar migración aditiva `008_account_notifications.sql`: registro cifrado de token por cuenta, buzón privado, idempotencia por evento y lectura por propietario.
- `009_staff_custom_roles.sql`: nombres de cargo propios con permisos seleccionados entre los aprobados; NUNCA `staff.write`, secretos del VPS ni autoridad de propietario.
- FCM de cuentas utiliza la clave de soporte existente para derivar una clave criptográfica distinta. Mantener `SPDECODE_SUPPORT_ENCRYPTION_KEY` secreta y estable, con copia **cifrada** fuera del VPS. No regenerarla si ya existe.
- Requisitos de entrega: `CLOUD_NOTICE_FCM_SERVICE_ACCOUNT_JSON`, `CLOUD_NOTICE_FCM_PROJECT_ID`, FirebaseApp Android configurada, ID y sender correctos, permisos de notificaciones y red disponible.
- Webhooks de pago verificados y respuestas administrativas crean avisos **en la misma transacción** que el hecho real. FCM se intenta después del COMMIT, fallo de FCM nunca anula una compra ni una respuesta.
- `GET /api/account/notifications`, `POST` de registro/desregistro/lectura y `GET /api/account/activity` exigen Better Auth; no se aceptan identificadores de cuentas enviados por el dispositivo.

## Historial y protección
- Historial por cuenta: pedidos y estados, movimientos de créditos, análisis APK y canjes. No incluye contraseñas, tokens secretos, contenido de los mensajes ni datos de tarjeta.
- No se crean copias de seguridad del almacenamiento general del teléfono. Proteger **solo** datos centrales: base comercial, claves de cifrado, credenciales de sesión/operador y persistencias de soporte. Realizar pruebas de restauración en un entorno aislado; respetar plazos de retención y borrado de cuenta.
- Mantener seguridad de Better Auth, Android Keystore y cifrado de conversaciones. Las notificaciones push no sustituyen autenticación ni autorizan transacciones.

## Recuperación de cuenta
- Una cuenta vinculada a Google puede recuperar acceso mediante Google OAuth y después administrar su contraseña en Seguridad; esto ya existe.
- Una cuenta exclusivamente de correo necesita un proveedor de correo saliente configurado para ofrecer restablecimiento seguro por enlace de un solo uso. Hasta habilitarlo, **no** simular envío ni exponer un endpoint de recuperación abierto.
- El usuario puede seguir utilizando su sesión válida con PIN/biometría sin almacenar la contraseña en texto plano.

## QA antes de activar en producción
1. Publicar código de web y APK de la **misma rama**. Validar migration, variables FCM y salud del servicio.
2. Con una cuenta de prueba, enviar respuesta soporte desde un operador autenticado. Notificación debe llegar con app fuera de pantalla, y abrir el buzón privado correcto.
3. Cuenta B nunca recibe evento, datos ni conversación de la cuenta A. Registrar/desregistrar token; cambiar de cuenta en el mismo dispositivo y confirmar asociación única.
4. FCM service account sin configurar: respuesta se guarda; buzón muestra el evento aunque no llegue push.
5. Simular pago confirmado, devolución y fallo de proveedor. Nunca notificar pago 'aprobado' antes de un webhook autenticado.
6. Probar permiso denegado y aceptación, canales silenciados, Doze, Wi-Fi y datos móviles, reinicio y **force-stop** (con su limitación).
7. Roles personalizados: asignación/permiso denegado, cambio de permisos invalida sesiones, jamás pueden crear o administrar otros cargos.
8. Comprobar CI, firma persistente, hashes de artefactos y pruebas de Android reales.

**Estado**: código QA, no implica que VPS ya esté desplegado ni que FCM esté correctamente provisionado. Métodos de pago reales siguen deshabilitados.

## Revisión posterior — registro FCM en sesiones y configuración real
- Después de **cualquier** inicio de sesión validado por Better Auth, `NativeCommerceAuth.account()` invoca `CloudNoticePush.syncAccount(context)`. Antes el callback solo se ejecutaba al arrancar Firebase o cambiar token, cuando quizá no había una sesión autenticada; esto impedía registrar la cuenta hasta reabrir la app.
- La sincronización comprueba consentimiento vigente, preferencia de notificaciones, sesión válida y FirebaseApp inicializada. Si faltan los identificadores públicos FCM, la aplicación omite el registro sin crashear.
- La ejecución QA `43436283496` produjo una APK en la que **no se encontraron** los identificadores públicos Firebase previamente configurados (APP_ID, PROJECT_ID y SENDER_ID) al inspeccionar los recursos y DEX del APK firmado. Este hallazgo no verifica el estado de GitHub Variables, pero indica que esa compilación no podía registrar FCM. Por eso CI ahora exige las cuatro variables `SPDECODE_NOTICE_FIREBASE_APP_ID`, `SPDECODE_NOTICE_FIREBASE_API_KEY`, `SPDECODE_NOTICE_FIREBASE_PROJECT_ID` y `SPDECODE_NOTICE_FIREBASE_SENDER_ID` antes de firmar.
- Los identificadores de Firebase Android son públicos. **Jamás** integrar `CLOUD_NOTICE_FCM_SERVICE_ACCOUNT_JSON` en la APK o en un commit. Debe permanecer exclusivamente en el VPS.
- Para verificar el despliegue: panel admin → Notificaciones → `Validar conexión FCM sin enviar` comprueba la cuenta de servicio; después se necesita un ensayo real con un dispositivo que haya habilitado notificaciones, cerrado la app normalmente y recibido una respuesta de soporte. La validación `validate_only` de FCM **no** prueba la entrega al teléfono.
- La interfaz y los canales respetan el ajuste de notificaciones del usuario. Los avisos de mensajes privados contienen solo texto genérico. En Android, forzar detención manual puede impedir cualquier entrega hasta la próxima apertura.
- Recuperación por Google está implementada; para restablecimiento por correo sin Google falta configurar y verificar un proveedor de correo saliente. Los respaldos fuera del VPS tienen pruebas criptográficas, pero no asumir programación automática de backups en producción sin verificar el destino, la retención y una restauración real.
