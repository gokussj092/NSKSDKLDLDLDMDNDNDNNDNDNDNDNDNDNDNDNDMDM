# Validación del panel conectado

- `run-native.sh`: lista de rutas y métodos, límites de cuerpo, consultas UTF-8 y rechazo de URL/identificadores no autorizados.
- `run-jni-host.sh`: carga de la biblioteca JNI y transporte HTTPS usando un `HttpsURLConnection` sintético en JVM; valida origen, credenciales en cuerpo POST, cookies, redirecciones, límites y errores. No contacta producción.
- Gradle `testDebugUnitTest`: importes exactos, IP literales y CSV.
- Gradle `connectedDebugAndroidTest`: campos de acceso editables, botón de acceso condicionado, fronteras JNI y persistencia cifrada con Keystore.
- El workflow abre además el **APK release firmado y minificado** en Android 15, comprueba la pantalla de acceso y ausencia de una excepción fatal.
- Backend: `node --test cloud/web/tests/mobile-admin.test.mjs cloud/web/tests/staff-console.test.mjs cloud/web/tests/c6-admin.test.mjs` desde la raíz.

Los fixtures no representan una sesión administrativa real. El informe final debe separar los resultados de estas pruebas de una comprobación autenticada en el VPS y de las pruebas en hardware físico.
