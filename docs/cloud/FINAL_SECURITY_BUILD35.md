# Integración final 1.1.24 (35)

Rama exclusiva: `feat/catalog-notifications-donations`. Se parte del HEAD real `54eee0ae74a5a4e599a5fddc24741ded38662faf`, posterior al commit de referencia `42cda84`. No se modifica main ni se despliega producción.

## Controles independientes

Panel → Infraestructura / Servicios reutiliza el componente `sp-admin-switch` existente:

| API V1 habilitada | Protección avanzada V1 | Admisión |
|---|---|---|
| Sí | No | Contrato V1 previo, autenticación, TLS y límites existentes |
| Sí | Sí | Operaciones autenticadas V1 requieren sesión vinculada y prueba V2 |
| No | No | V1 se rechaza, incluidas salud, autenticación y rutas desconocidas |
| No | Sí | V1 se rechaza; disponibilidad tiene prioridad |

Valores iniciales con almacén nuevo: **habilitada, protección avanzada desactivada**. No dependen de la versión del APK ni de los antiguos flags de entorno `CLOUD_LEGACY_API_ENABLED`/`CLOUD_V1_REQUIRE_BOUND_SESSION`, que ya no gobiernan estos controles. Una política V1 existente se conserva al migrar.

El archivo independiente `/app/provider-control/v1-protection.json` contiene solo versión, ambos estados y revisión. No se cambia ningún ajuste de proveedores. Las modificaciones requieren administrador, Origin/CSRF, confirmación explícita, revisión esperada y límite de frecuencia. Los cambios simultáneos obsoletos se rechazan con 409; el cliente recupera el estado real. Auditoría acotada sin tokens, contraseñas ni datos privados.

Escrituras con archivo temporal, fsync, rename y fsync del directorio. Bloqueos de kernel `flock`, sobre un descriptor heredado, serializan procesos y se liberan tras una caída; los archivos de lock no se eliminan. Un fallo/corrupción del almacén produce 503 para V1, sin adoptar valores permisivos.

El proxy Next aplica el control a todos los métodos y prefijos V1 normalizados, sin excepción de health/ready. Nginx también consulta un subrequest interno antes de las rutas V1 exactas, prefijos y redirecciones HTTP: 410 con `V1_API_DISABLED`, 503 si la política no puede verificarse. El endpoint interno es solo lectura y Nginx impide su acceso público. V2 usa su contexto autenticado en proceso y conserva su política independiente. La política se verifica al admitir cada petición; no se recuperan bytes de respuestas ya transmitidas.

La comprobación de vida del contenedor y los scripts operativos pasan a `/api/health/live`, fuera de V1. Las comprobaciones de disponibilidad funcional de V1 continúan siendo pruebas de V1 y se rechazan al retirarla.

## Avisos persistentes y Firebase

El volumen dedicado `notice-feed` contiene `/app/notices/feed.json`, con hasta 20 avisos y caducidad lógica de 7 días. Solo admite el esquema cerrado de avisos. No contiene cuentas de servicio ni credenciales Firebase. Redis mantiene tmpfs y persistencia desactivada para sesiones, desafíos, límites y auditoría temporal.

La primera lectura/publicación migra los avisos válidos de `spnotice:feed:v1`, si existen. La migración se confirma en disco antes de continuar. Después se usa el archivo, incluso tras perder Redis. Publicaciones concurrentes comparten bloqueo de kernel y no pierden actualizaciones; un UUID repetido es idempotente. El aviso se confirma antes de contactar FCM: un fallo de Google no borra el aviso. Corrupción de datos devuelve error y conserva el archivo dañado para recuperación manual, sin sustituirlo por una caché antigua.

FCM HTTP v1 envía exclusivamente `noticeId` por `spdecode-notices-v1`. El contenido se obtiene con la operación V2 17 autenticada. El botón administrativo **Verificar conexión FCM** usa `validate_only`: comprueba autorización/formato sin emitir avisos; no acredita recepción en Android.

Proyecto esperado en el APK: `sp-decode-android`, remitente `78511444369`, paquete `com.ghostdeveloper.spdecode`. Identificadores públicos desde variables de Actions; la cuenta de servicio privada permanece en la VPS. Se conservan consentimiento, permiso Android13+, desactivación, deduplicación y recuperación WorkManager. Las consultas de 15 minutos pueden generar 96 comprobaciones diarias por instalación antes de reintentos: revisar la cuota Play Integrity al aumentar usuarios.

La configuración real en la VPS y la recepción en teléfonos requieren acceso al entorno desplegado. Las pruebas aisladas no se presentan como envíos reales ni como recepción confirmada.

## Artefactos privados y firma

Validate llama al workflow privado en esta misma rama tras sus dos trabajos generales. El preparador exige además las once validaciones independientes del SHA exacto y rechaza un HEAD obsoleto. No necesita una nueva rama ni un dispatch externo. La entrada manual `cloud-real-api-test-apk.yml` delega en el mismo flujo canónico; deja de reescribir la versión a 1.2.5-qa (33) y no habilita el lanzador QA en este artefacto. Un dispatch manual de Actions conserva los mismos controles.

Secretos obligatorios: `SPDECODE_SIGNING_KEYSTORE_BASE64`, `SPDECODE_SIGNING_STORE_PASSWORD`, `SPDECODE_SIGNING_KEY_ALIAS`, `SPDECODE_SIGNING_KEY_PASSWORD`. Solo se informa el nombre de cualquier secreto ausente. No se crea otra keystore.

Se comprueba el certificado permanente SHA256 `0fa9f07f2c47464925f3a7b222c9a39ef887738f678b9c918ec6c4fb96162260`, APK/AAB, identidad 1.1.24 (35), JNI/DEX/ELF, alineación de 16 KiB y presencia de Firebase/notificaciones. Los archivos y SHA256SUMS quedan exclusivamente en el artefacto privado de Actions. Ningún workflow de esta rama publica una Release pública ni una actualización Play estable automáticamente.

La limpieza autorizada se limita a `fix/v1-protection-notice-persistence-build35`: verifica SHA original, ascendencia y fuerza con lease exacto al eliminar; si cambió, conserva el trabajo. Solo ese trabajo tiene permiso de escritura de contenidos. El trabajo de firma conserva permisos de lectura.

## Preparación del despliegue, sin ejecutarlo

1. Confirmar el HEAD efectivo de `/opt/spdecode/repo` y la configuración actual sin imprimir secretos. El commit de producción informado por el propietario es `12b838ade20a51c6c7828b624feaa7bbd77f3edc`.
2. Revalidar el respaldo RDB informado `/root/spdecode-migration-backup/redis/redis-live-20261029T035848Z-3638991.rdb` y su checksum conservado. El propietario informó restauración aislada de 130 claves; esta sesión no la vuelve a certificar sin conexión a la VPS.
3. Respaldar los archivos de políticas/proveedores, avisos si ya existe el volumen y configuración Nginx. Inspeccionar nombres reales de volúmenes antes de copiarlos. No borrar ni recrear Redis ni usar `down -v`.
4. Probar la imagen y el Nginx generado en un entorno aislado. Verificar `http_auth_request_module`, permisos node de ambos volúmenes y salud independiente. Al actualizar solo web, mantener el Redis existente para que el feed anterior siga disponible durante la migración.
5. Validar los cuatro estados y un cliente Android 1.1.21 (32) real antes de activar protección. La compatibilidad por defecto no exige V2 a ese cliente. V2 mantiene su mínimo y verificaciones independientes.
6. Al desplegar, usar un SHA fijado y cambiar solo servicios necesarios. No ejecutar desde esta sesión un despliegue a producción. Un APK con transporte V2 necesita el backend V2 correspondiente: no se da por probado contra el backend antiguo solo por instalarlo.
7. Reversión: conservar imagen/SHA y Nginx anteriores, respaldos y esquema anterior de políticas. Una versión antigua puede no entender el archivo de políticas v2; no descartar el volumen ni restaurar políticas permisivas por error. Probar la reversión en aislamiento y mantener V1 bloqueada si ese es el estado deseado.

Pruebas físicas pendientes: actualización de APK con el certificado instalado, Firebase con app abierta/cerrada y permisos denegados, persistencia de avisos tras reinicio, flujo con Play cerrado y artefacto protegido por LIAPP. Una APK firmada permanentemente puede tener un certificado distinto del APK instalado por Play App Signing; comprobar ambos antes de sustituir una instalación existente.
