# V2 beta de Telegram y Google Play Integrity

Los controles en Administración → Infraestructura son independientes:

1. API V1 habilitada: bloqueo centralizado de todas las rutas V1.
2. Protección avanzada V1: requiere sesión y prueba vinculadas, no desactiva V1.
3. API V2 habilitada: bloqueo centralizado de todas las rutas V2.
4. Exigir Google Play Integrity en V2: activado por defecto. Al desactivarlo, abre una ventana beta de hasta 15 días que caduca automáticamente.

El interruptor Play de V2 no modifica la política de Play V1 ni la disponibilidad general V2. Rehabilitar Play revoca las sesiones beta en su próxima solicitud.

## Requisitos beta sin Play

- APK firmada con uno de los certificados SHA-256 permitidos en el backend.
- CLOUD_GOOGLE_PLAY_PACKAGE=com.ghostdeveloper.spdecode.
- CLOUD_PLAY_CERT_SHA256 con huellas de Play App Signing y APK externo oficial, cuando difieran.
- Android Keystore y cadena verificable de atestación TEE o StrongBox.
- Identidad de aplicación verificada en el certificado de atestación, incluyendo paquete, firma y versionCode mínimo.
- Prueba de posesión ECDSA por solicitud, límites de IP, claves y sesión, anti-replay y worker aislado.

Sin Play activo no se consulta licenciamiento o reconocimiento de Google Play. Tampoco se solicitan tokens Standard Integrity por operación, que dependen de Play. Esta protección es deliberadamente inferior a la verificación de Play.

Si el dispositivo no puede proporcionar atestación hardware, se rechaza; no se realiza downgrade automático a V1 ni se permiten sesiones anónimas.

## Preparación para despliegue

1. Confirmar dos huellas SHA-256 públicas: certificado de firma de aplicación en Play Console y certificado del APK externo firmado por GitHub Actions. No son necesariamente iguales.
2. Confirmar número del proyecto Google Cloud vinculado a Play Integrity en Play Console; el número de Firebase no demuestra por sí solo la vinculación.
3. Preparar huellas y proyecto con cloud/infra/vps/prepare-hardware-security.py, tras respaldar cloud.env.
4. Cuando Play sea obligatorio, instalar una cuenta de servicio autorizada para Play Integrity API mediante spdecode config google-service-account /root/play-service.json. No reutilizar la cuenta FCM sin verificar los permisos.
5. Construir y verificar el contenedor key-attestation con estado READY antes de probar la beta.
6. Compilar APK/AAB con la keystore permanente; comprobar certificado, funcionamiento en dispositivo físico y CI.
7. Desplegar backend con respaldo y rollback, preservando Redis; sincronizar Nginx para publicar V2 después.

No desactivar CLOUD_KEY_ATTESTATION_REQUIRED. El botón no crea credenciales ni configura números de proyecto faltantes.
