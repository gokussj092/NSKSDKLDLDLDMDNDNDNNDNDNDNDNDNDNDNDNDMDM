# SP-DECODE 1.1.24 (35) — integración de seguridad y reparación de inicio

## Estado comprobado en la VPS

El código fuente del servicio Key Attestation fue actualizado a
`4564caeec0a9e769f2de017e7fc71dc4f71c1dda` y el usuario confirmó:
`/ready` HTTP 200, una clave de hardware registrada, sesiones V2 exitosas,
cinco descifrados y recepción de dos avisos. Estos resultados validan la
*admisión de beta externa*, no la admisión estricta Play Integrity.

## Tres comprobaciones y cuándo se ejecutan

1. **Atestación de clave de hardware**: cadena X.509 válida, raíz confiable,
   desafíos nuevos, identidad de paquete/firma, versión, arranque verificado,
   TEE/StrongBox, revocaciones, parche del sistema vigente y parches opcionales
   de arranque/proveedor validados cuando se aportan. Obligatoria también
   durante la beta externa. El parche evita exigir campos opcionales.
2. **Play Integrity clásico**: veredicto remoto de Google, vinculado al nonce
   para emitir la sesión. Requerido cuando la política Play Integrity está
   activada.
3. **Play Integrity estándar para operaciones protegidas**: requestHash
   vinculado a operación y cuerpo. Se utiliza únicamente cuando la política
   Play Integrity está activa Y CLOUD_ACTION_INTEGRITY_REQUIRED no es false.

La firma local de Android, clave de hardware Android Keystore, prueba de
posesión por solicitud, tokens efímeros y limitación de solicitudes son
controles adicionales; no sustituyen las verificaciones de Google.

**No presentar el éxito en una APK externa como prueba de las tres capas.**
Activar Play Integrity completo exige prueba desde Google Play con el
certificado de firma distribuido por Play. Una beta que lo desactiva mantiene
hardware obligatorio, y nunca se permite un fallback silencioso de V2 a V1.

## Incidencias integradas

- Key Attestation: aceptará certificados legítimos sin vendorPatchLevel /
  bootPatchLevel, pero rechazará valores obsoletos cuando estén presentes.
- Seguridad del servidor: sólo se registran códigos agregados de rechazo
  sin certificados, IP, identificadores o datos de sesión.
- Signed APK: la compilación anterior omitía el digest en BuildConfig y la
  actividad se cerraba. Los workflows normales ya proporcionaban ambos
  digests; ahora fallarán explícitamente si BuildConfig release no incorpora
  las dos huellas esperadas, antes de publicar artefactos.
- Notificaciones: el usuario recibió 2/2 tras recuperar la sesión V2. La
  entrega puede ocurrir por FCM o consulta periódica; el evento no demuestra
  por sí mismo que el mensaje push haya llegado por FCM.

## Estado de versiones y publicación

El APK/AAB STARTUP-FIX ya distribuido procede de un workflow especial aislado
y verificado. Este cambio no genera nuevas APK, no cambia versionCode 35, no
actualiza producción automáticamente ni modifica secretos. El servicio en VPS
se validó con Docker; no es una validación del flujo completo Play Integrity.

## Riesgos y validaciones restantes

Un cliente Python sin un hardware genuino y la clave privada válida no puede
inventar una cadena de certificación reconocida. Un atacante con acceso a un
dispositivo auténtico podría intentar actuar como intermediario; no existe
protección absoluta frente a instrumentación del propio dispositivo.
Pendiente una prueba real desde Google Play con las tres capas activadas.
