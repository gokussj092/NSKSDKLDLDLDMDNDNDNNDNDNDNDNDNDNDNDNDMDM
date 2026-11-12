# F7 — Continuidad del análisis APK/APKS y exclusión de un único trabajo (2026-11-07)

**Rama:** `feat/nuevas-integraciones`. **Estado:** código integrado; validación de CI, ejecución en dispositivo real y despliegue de VPS aún pendientes. No se ha fusionado `main`.

## Requisito exacto

Solo una APK/APKS activa a la vez en la prueba privada: desde que se acepta el archivo hasta que exista un resultado final `COMPLETED`, `FAILED` o `REJECTED`. Se aplica **en el servidor**, con límite global QA `MAX_ACTIVE=1`, y **en Android**, con un único checkpoint y `WorkManager.enqueueUniqueWork`. No se permite iniciar otro trabajo porque se haya cerrado la pantalla, suspendido Android o perdido la conexión.

La fase continúa sin login, créditos, compras, códigos regalo, registro de dispositivos o introducción de tokens. Se conservan V2 HPKE, PoP, atestación y Play Integrity según la política existente. La identidad técnica para aislar trabajos se obtiene automáticamente de la sesión V2 ya verificada; la credencial privada entre contenedores se genera automáticamente con `spdecode apk-qa enable`. El máximo es **100,000,000 bytes**, únicamente APK/APKS; XAPK y ZIP directos no están habilitados.

## Continuidad incorporada

1. **Antes de transmitir**, Android conserva un único trabajo local en `noBackupFilesDir`, cifrado AES-256-GCM con clave no exportable de AndroidKeyStore. Guarda URI de OpenDocument con permiso persistente, ID aleatorio de idempotencia, SHA-256, capacidades temporales, offset confirmado, eventos y último informe. Nunca guarda secretos en WorkManager Data, logs, Room ni SharedPreferences.
2. **Subida**, en `ApkQaWorker` único y con red disponible: el servidor devuelve `nextChunk`, `receivedBytes` y `chunkBytes` después de validar la propiedad del trabajo. Android vuelve a calcular SHA-256 del archivo seleccionado y salta únicamente los bytes confirmados. Fragmentos de 2 MiB se autentican individualmente; no hay reanudación de bytes arbitrarios.
3. **Inicio idempotente**, `clientStartId`: el servidor deriva una capacidad con HMAC de secreto interno y el identificador de dispositivo, de forma que el mismo inicio repetido tras perder una respuesta regresa el mismo trabajo incluso cuando ya terminó. No se vuelve a cobrar ni crear otro trabajo.
4. **Después de confirmar el envío**, el servicio conserva en disco un estado de procesamiento y eventos verificados. Al arrancar el proceso, `_recover_jobs` reconcilia `PROCESSING`: conserva un informe ya escrito, vuelve a analizar el mismo archivo verificado si aún existe, o registra un error terminal cuando falta el archivo. Los APK de entrada se borran tras terminar. El volumen de jobs se conserva al reiniciar el contenedor.
5. **Regreso a Android**, `MainActivity` observa el checkpoint local y reconstruye la pantalla AMOLED, eventos, progreso y último JSON. WorkManager puede continuar o reintentar si el sistema permite ejecución de red; no se asegura ejecución inmediata durante Doze, restricciones de batería o falta de conexión. Al reconectar, no se crea un trabajo distinto.
6. **Solo al guardar cifrado el informe terminal** se desbloquea la opción de subir otro APK. Si el checkpoint está dañado, la UI falla de manera cerrada; no autoriza un segundo trabajo a ciegas. Se retiró el botón Cancelar para no confundir la cancelación local con el final de un análisis remoto.

## Pruebas automatizadas y cobertura

- `tests.test_f7_apk_qa_service`: exclusión de trabajos por dispositivo y global, rechazo de duplicados, continuidad de índice y bytes, reinicio durante procesamiento, error terminal por archivo perdido, y reintento idempotente después de completar el resultado.
- `tests.test_f7_apk_qa_android_resume`: contratos estáticos de Keystore, almacenamiento sin respaldo, WorkManager único, conexión existente y bloqueo de UI. Son **pruebas de fuente**, no sustituyen instrumentación Android.
- Workflow `F7 APK QA First-Pass Real Integration`: pruebas Python, pruebas del gateway V2 Node, compilación real Android/JNI y análisis del propio APK de laboratorio. Revisar conclusión de jobs antes de marcar PASS.

## Pendientes y limitaciones

- No se ha comprobado en un teléfono físico la ejecución automática de WorkManager en segundo plano, Play Integrity en segundo plano, desconexión 4G/Wi-Fi, rotación, reinicio del sistema, URI de cada proveedor o batería restringida.
- El análisis sigue siendo estático preliminar: **no realiza JADX/Ghidra, ejecución de scripts de terceros, análisis de métodos VPN ni descifrado automático**. Tampoco hay cambio/reintento de algoritmos que reportar.
- Se conserva **el último informe**, no un historial ilimitado de trabajos APK; la implementación comercial y el cifrado de APK temporal **en reposo en el servidor** quedan pendientes. Informe remoto hasta 12 h con política de limpieza, y carga inactiva caduca. La clave de atestación/dispositivo y el secreto interno deben persistir entre reinicios para recuperar un trabajo.
- Si la fuente SAF desaparece o no concede lectura persistente, reanudar la **subida** es imposible sin volver a seleccionar el mismo archivo; servidor mantiene el bloqueo hasta su caducidad/resultado. Si el servidor pierde el volumen de trabajos, no puede recuperarlos mágicamente. No se realiza cancelación remota de QA en esta subfase.
- El VPS reducido se debe dimensionar antes de activar `apk-qa`. No instalar ni desplegarlo automáticamente en producción sin recursos comprobados.

**Criterio de aceptación:** runs CI completos verdes, APK firmado e instalado, envío real de 100 MB dentro de los límites, salida/reentrada de Activity, cierre forzoso del proceso, reinicio del servicio QA, bloqueo de segundo APK y recuperación del informe. Hasta entonces: **IMPLEMENTED / NOT CERTIFIED**.

## Activación sin inscripción ni tokens manuales

Tras las pruebas CI y la comprobación de recursos, usar `sudo spdecode update all feat/nuevas-integraciones`, seguido de `sudo spdecode apk-qa enable`. La CLI genera una credencial aleatoria solo entre los contenedores, preserva los secretos ya configurados del servicio, configura el interruptor de QA y comprueba salud. No exige copiar un ID o introducir un token en el teléfono. Ver estado sin secretos: `sudo spdecode apk-qa status`. **La seguridad no depende de que el endpoint sea desconocido**; el túnel V2 sigue autenticando y cifrando las solicitudes.
