# Reanudar integración 1.1.21

Cuenta autorizada: Goku (`gokussj092`), repositorio migrado y misma rama
`feat/temporary-original-app-config-export-lab`. No fusionar ni desplegar VPS.
El usuario autorizó implementar Android/API y actualizar workflows a 1.1.21;
notificaciones del sistema se aplazan expresamente.

## Recuperación y respaldo

La limpieza eliminó el checkout anterior. Se recuperaron los 1981 archivos
del commit `7a17961bf7d806454940c68302e54841c3d9c972` mediante el conector Goku,
verificando cada objeto Git contra su SHA-1. El índice y los árboles coinciden.
Los paquetes privados de pruebas siguen recuperables desde las entregas
anteriores; no se incluyen en commits ni en logs. Una copia local por sí sola
no garantiza sobrevivir otra limpieza: cada hito se guarda en esta rama.

## Hito 1: worker de exportación

- Adaptadores en `cloud/workers/python/exports/` para HC, Dark, EHI y NPV.
- Artefactos preparados después de un descifrado válido, en proceso aislado,
  límite 1 MiB y presupuesto de respuesta completa inferior a 6 MiB.
- HC reconstruye n11 abierto con HTML y retira password/HWID después de
  autenticar; conserva perfiles, expiración y secciones desconocidas.
- NPV puede reconstruir NPVO1 después de passphrase o private key v5/v6
  validada por el lector existente; las políticas no representables se rechazan.
- EHI usa la ruta abierta + HTML aceptada. La derivación de HMAC usa la
  huella **pública** del certificado auditado, sin necesitar distribuir su APK.
- Dark conserva la política sin banner. El bridge distingue JSON abierto de
  los contenedores protegidos antes de elegir el lector.
- 10 pruebas nuevas pasan. Las cuatro muestras originales recuperadas de
  las entregas privadas producen artefactos locales verificados.
- Las ampliaciones de credenciales tienen comprobación criptográfica local;
  todavía requieren nuevas importaciones manuales en las apps originales.

## Decisión de historial

Se mejora el plan de RAM temporal a petición del usuario: almacenar el
artefacto preparado dentro del registro cifrado del historial. El archivo
podrá guardarse después de reiniciar, sin conservar la contraseña/HWID/key
de apertura. Los registros históricos antiguos sin artefacto requieren
volver a descifrar la fuente. No reconstruir desde JSON de presentación.

## Hito 2: API, catálogo y panel

- Protocolo aditivo `X-SPDecode-Compatible-Export: 1` y versión >=1.1.21.
  Los clientes anteriores conservan el esquema y la versión de catálogo.
- El panel administra habilitación y versión mínima (nunca inferior a 1.1.21).
  Configuración desactivada por defecto, persistente en `provider-control`,
  escrituras atómicas, revisiones concurrentes y autenticación/CSRF existentes.
- El apagado de exportación conserva el descifrado y su JSON. La capacidad
  nueva no reemplaza autenticación, mantenimiento ni autorización de archivos.
- Interruptor de emergencia `CLOUD_COMPATIBLE_EXPORT_LOCKED` conectado al
  compose y a la allowlist del CLI; no se ha cambiado ningún VPS.
- Las 355 pruebas Node del sitio/API pasan, incluyendo versión antigua,
  versión mínima, manipulación de opciones, persistencia y controles del panel.
  `next build` también pasó. La compilación no activa servicios externos.

## Trabajo Android presente y pendiente de cerrar

1. DTO Android, artefacto cifrado en historial, guardado binario y opción
   Exportar para [aplicación], también desde el historial.
2. Mantener los nueve archivos C0 congelados: integrar la fila por las copias
   Cloud generadas en Gradle y actualizar sus pruebas/anchors.
3. Versión 1.1.21 / versionCode 32 y workflows/auditorías correspondientes.
4. Regresiones, compilación Kotlin Cloud si hay SDK accesible, pruebas
   gateway-worker y verificación de que los clientes antiguos no reciben
   el nuevo esquema. No publicar APK/AAB ni activar servicios en VPS.

Este archivo debe actualizarse en cada hito; los commits remotos son el
respaldo durable del código. No guardar el repositorio otra vez como archivo
duplicado en las entregas de documentos.
