# Android 1.1.24 (35): catálogo, avisos y ajustes

La rama parte del PR104 y conserva V1, sus controles del panel y la interfaz C0 original. Las diferencias de presentación se aplican a copias generadas para Cloud con anclas únicas comprobadas al compilar. Se añaden dos tarjetas de Ajustes sin cambiar navegación, colores o estructura general.

- Donaciones: Binance, Ghost Developer, ID 1233239512, copia explícita; PayPal Próximamente. No contiene direcciones de criptomonedas ni inicia pagos.
- Comunidad: https://t.me/+Ntu6EJMirrAwMzgx. Contacto y canal del desarrollador se conservan.
- Actualizar/Actualizando: control compacto en formatos y servidores. Sin catálogo y durante una descarga, indicador central. El porcentaje corresponde a registros procesados y sus iconos verificados; no simula bytes ni usa temporizadores. La comprobación de versión permanece indeterminada.
- Exportación compatible hc/ehi/dark/npvs: conserva el nombre original y añade ` (Unlocked)` antes de la extensión. El contenido binario y su verificación no cambian. Después de la primera exportación correcta se ofrece activar avisos; rechazarlo no afecta al archivo guardado.

## Catálogo

Cada solicitud de catálogo/icono del cliente nuevo incluye una clave pública P256 efímera. El servidor comprime el JSON con gzip y usa ECDH P256, HKDF-SHA256 (sal aleatoria de 32 bytes) y AES-256-GCM (IV aleatorio de 12 bytes, etiqueta 128 bits). El AAD liga propósito, ambas claves públicas y longitud original. La aplicación limita el descifrado y descompresión a 4 MiB y verifica hashes/esquemas antes de guardar el catálogo. TLS autentica al servidor; no hay contraseña compartida compilada en el APK.

Las sesiones V2 con versionCode >=35 exigen la negociación. El cliente nuevo rechaza respuestas sin sobre cifrado. V1 y APK anteriores mantienen su contrato para permitir la transición solicitada; sus respuestas originales viajan por HTTPS. No se retiran automáticamente.

La caché SVC2 comprime antes de AES-GCM con clave Android Keystore no exportable, nombre autenticado, almacenamiento sin copias y escritura atómica. Lee SVC1 para conservar descargas existentes. El catálogo se tiene que descifrar en memoria para visualizarse: esta protección aumenta el coste de extracción, no hace imposible la instrumentación de un teléfono autorizado. La ofuscación adicional de LIAPP se valida sobre el artefacto final.

## Publicación de notificaciones

En Panel → Infraestructura hay un formulario de título (80 caracteres) y mensaje (500). Requiere sesión administrativa, Origin/CSRF, límite de 5 publicaciones/minuto y bloqueo Redis. Los avisos caducan a los 7 días; se retienen los 20 últimos. Redis debe tener la persistencia operativa habitual. No admite enlaces, intents o destinos ejecutables como campos adicionales. No uses el canal para secretos.

La app obtiene el contenido por la operación V2 17: exige sesión ligada a clave, prueba por petición y límites de metadatos. No se crea un endpoint V1 público sin autenticación. Android comprueba el consentimiento Cloud y el permiso antes de consultar o mostrar. El canal muestra texto, abre exclusivamente MainActivity y conserva identificadores para no repetir avisos.

Sin Firebase, Android consulta al volver a la app y mediante WorkManager cada 15 minutos como mínimo. Doze, restricciones de batería y detener forzosamente la app pueden retrasar o impedir esas tareas. No es entrega inmediata.

### Activar Firebase Cloud Messaging (opcional)

No se ha creado ni configurado un proyecto Firebase con este cambio. Para la entrega push:

1. Registra `com.ghostdeveloper.spdecode` en tu proyecto Firebase. Habilita FCM HTTP v1. Comprueba restricciones de API de la clave pública para tu aplicación y firmantes finales (incluido Play App Signing/LIAPP).
2. Al compilar Cloud, proporciona las cuatro propiedades Gradle públicas: `noticeFirebaseAPP_ID`, `noticeFirebaseAPI_KEY`, `noticeFirebasePROJECT_ID`, `noticeFirebaseSENDER_ID`. Se aceptan juntas o ninguna. No se necesita google-services.json ni se incluye una cuenta de servicio en Android. Los flujos firmados las leen de las variables de repositorio `SPDECODE_NOTICE_FIREBASE_APP_ID`, `SPDECODE_NOTICE_FIREBASE_API_KEY`, `SPDECODE_NOTICE_FIREBASE_PROJECT_ID` y `SPDECODE_NOTICE_FIREBASE_SENDER_ID`. Los disparadores y restricciones de publicación existentes se conservan.
3. En la VPS, configura `CLOUD_NOTICE_FCM_SERVICE_ACCOUNT_JSON` con una cuenta de servicio del mismo proyecto y permiso mínimo de envío FCM. Compose solo la pasa al servicio web. Esta credencial es diferente de la de Play Integrity; no la publiques ni la incorpores al APK.
4. Activa notificaciones en Ajustes y concede POST_NOTIFICATIONS en Android13+. Firebase no se inicializa antes del consentimiento. La suscripción recibe solo un UUID de aviso por el tema `spdecode-notices-v1`; el contenido se obtiene después de la API autenticada. No envía archivos ni contraseñas a Firebase.
5. Publica un aviso desde el panel y comprueba su recepción con app abierta y cerrada, caducidad, duplicados, denegación del permiso y revocación Cloud. Una señal FCM enviada no certifica que el teléfono la haya recibido. Si falla FCM, el aviso publicado queda disponible por consulta periódica.

La integración usa prioridad normal para no prometer entrega inmediata durante Doze. La política de privacidad ES/EN declara el uso opcional de Firebase y sus identificadores. Revisa Data Safety de Play y cualquier licencia/SDK LIAPP antes de publicar. No se ha enviado ningún aviso real, fusionado el PR, desplegado la VPS ni publicado un artefacto por preparar este cambio.

## Validación

Pruebas Node: Unicode, claves efímeras distintas, compresión, receptor incorrecto, alteraciones de AAD/cifrado, claves inválidas y límites; autenticación/CSRF/idempotencia/caducidad del publicador; nueva operación protegida. Vector sintético Node → Android, pruebas de caché SVC1/SVC2/tampering, UI Compose y nombres Unicode en instrumentación API35. Las claves del vector son exclusivamente de prueba.

La configuración FCM real, permisos, recepción en teléfonos físicos, distribución por Play cerrada y la transformación de LIAPP requieren validación con tus credenciales y artefacto protegido. Se mantiene NO-GO para publicación estable.
