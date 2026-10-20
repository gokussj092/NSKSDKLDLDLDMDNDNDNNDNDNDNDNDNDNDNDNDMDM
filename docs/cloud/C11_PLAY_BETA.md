# SP-DECODE — publicación cerrada de Google Play y APK beta

Operador/editor: **Ghost Netzor Studio**. Nombre comercial del desarrollador; no altera el
paquete **`com.ghostdeveloper.spdecode`** ni el nombre visible SP-DECODE.
Rama: `feat/austroplus-vpn-13-0-1-decoders`; PR #96 abierto y sin fusionar.

## Archivos
El workflow `.github/workflows/play-beta-artifacts.yml` compila **dos formatos a partir
del mismo código, versión 1.1.4, versionCode 25, y Android 16 (targetSdk 36)**:
- `SP-DECODE-v1.1.4-play-closed-test-signed.aab`: subir al track **Prueba cerrada**
  en Google Play Console.
- `SP-DECODE-v1.1.4-beta-external-signed.apk`: distribución fuera de Play.
- `SHA256SUMS.txt` y `SIGNATURE_VERIFICATION.txt`.

Los dos usan **la clave permanente** de GitHub Secrets `SPDECODE_SIGNING_*`, sin
generar otra ni almacenar contraseñas en el repositorio. El AAB se firma para subir a
Play; Google Play firma los APK que entrega a los dispositivos.

### IMPORTANTE: firma de Google Play
Si el certificado de **Firma de aplicaciones** que Play Console asigna es distinto
del certificado de **Clave de subida**, copia su huella pública SHA-256 desde
`Play Console > Configuración > Integridad de la aplicación > Firma de aplicaciones`
(según interfaz) y configúrala como variable de repositorio
`SPDECODE_PLAY_APP_SIGNER_SHA256` (64 caracteres hexadecimales, sin dos puntos).
Ejecuta nuevamente el workflow antes de usar el AAB: el APK que distribuye Google
debe estar autorizado por `ReleaseIntegrity`. Una primera subida NO comprueba
automáticamente la ejecución de la APK firmada por Play.

Google Play puede distribuir el mismo paquete con otro certificado: las
instalaciones externas podrían necesitar desinstalar antes de instalar la versión
Play, con pérdida de los datos locales si los certificados difieren. Si necesitas
actualizaciones en sitio sin perder datos, configura en Play App Signing el
certificado de firma de aplicación original, siguiendo las opciones que Play
Console presente, ANTES de la primera publicación.

## Configuración del VPS durante las pruebas
Desplegar la versión nueva de API y activar explícitamente
`CLOUD_BETA_ADMISSION_ENABLED=true` en las variables del servicio web Docker,
**sin cambiar otros secretos**. En `/admin/system` usa el nuevo interruptor:
**Exigir Google Play Integrity** → desactivar. Ese acceso beta dura hasta
**15 días** y vuelve a exigir Play Integrity automáticamente si no se renueva.
Puedes reactivarlo en cualquier momento. Sin esta variable (o cuando el plazo
venza) el interruptor falla cerrado, manteniendo protección por defecto.

ADVERTENCIA: con la verificación desactivada **cualquier cliente capaz de enviar
peticiones HTTP puede solicitar una sesión**. Esto no confirma la autenticidad de
la APK; se mantienen los límites por IP, los desafíos de un solo uso, las sesiones
firmadas de cinco minutos, y la privacidad de los motores. Vigila el consumo de
la VPS. Si el cambio de política ocurre durante una sesión existente, la sesión
puede permanecer válida hasta cinco minutos.

Al publicar en producción, vuelve a activar la verificación, configura
`CLOUD_GOOGLE_SERVICE_ACCOUNT_JSON` y comprueba el certificado de Play. Los
usuarios de APK externas perderán acceso a **nuevas** sesiones sin Play.
No hay un bloqueo impuesto por Google Play al APK externo por este control:
la API decide el acceso. QA temporal continúa como mecanismo independiente.

## Pasos Play Console
1. Crear la ficha **SP-DECODE**, editor Ghost Netzor Studio y paquete
   `com.ghostdeveloper.spdecode`. Completar ficha, icono, capturas, política
   de privacidad y declaración de tratamiento de datos / contenido.
2. Registrar la firma Play, comparar huella SHA-256 e introducir variable de
   GitHub si es distinta. Ejecutar el workflow y obtener el AAB firmado.
3. Subir el AAB en **Prueba cerrada**. Añadir como mínimo **12 probadores**
   registrados (opt-in) durante **14 días continuos** si tu cuenta es personal
   creada después del 13-11-2023. No basta compartir la APK externa: no cuenta
   como inscripción a prueba cerrada.
4. Ofrecer un canal real de comentarios, probar login, API, archivos protegidos,
   Server VPN y novedades. Después de 14 días **solicitar** acceso a producción,
   que está sujeto a revisión, no garantizado automáticamente.
5. Incrementar `versionCode` para cada AAB nuevo; mantener siempre
   `applicationId` y la política de firma coherente.

**No publicar ni fusionar automáticamente**. La compilación produce artifacts
del workflow, no una subida automática a Play.

## Requisito Android 16 (Google Play, octubre de 2026)
A partir del 31 de agosto de 2026, las apps nuevas de teléfono/tablet
necesitan `targetSdk 36`. El proyecto usa AGP 8.9.2 (compatible con API 36),
`compileSdk 36` y conserva `minSdk 24`. Este cambio se prueba en CI, pero
se deben comprobar los gestos de navegación, barras de sistema y diálogos
en un dispositivo Android 16 antes de publicar.
