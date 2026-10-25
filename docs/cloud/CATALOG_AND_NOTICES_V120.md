# SP-DECODE 1.1.20 (31) — Catálogo de archivos/textos, avisos y versión Android

Estado: **PR #99 — preproducción; sin fusión, despliegue ni publicación**.

## Catálogo remoto (servidor de SP-DECODE)

Un mismo `catalogVersion` controla la distribución HTTPS de:
- `formats` — extensiones de archivos y credenciales públicas declarativas.
- `textFormats` — prefijos de texto y enlaces Cloud compatibles con el endpoint
  de texto del worker, declarados en `cloud/web/content/text-formats.json`.
- `apps` — fichas públicas e iconos originales cuya huella SHA-256 es verificada.

Cada entrada de texto contiene únicamente `prefix`, `name`, `suffix`
y `kind` (`text` o `cloud`). **Nunca** rutas de Python, código, endpoints
arbitrarios, secretos, URL de proveedor o instrucciones ejecutables. El backend
decide si el descifrador realmente existe y permite esa operación: descargar
el catálogo **no** instala algoritmos ni descifradores nuevos en Android.
Para añadir un protocolo de texto soportado por los workers del VPS basta con
publicar sus metadatos y aumentar `CATALOG_VERSION`. Para un nuevo tipo de
importación Cloud que necesite un endpoint diferente, todavía hará falta
implementar el broker HTTPS seguro correspondiente en el servidor.

Con `CATALOG_VERSION=48`, la app admite también snapshots antiguos sin
`textFormats` durante la migración, recurriendo a sus prefijos históricos.
La cache sigue cifrada, se verifica el contrato, se bloquean retrocesos de
versión y se verifican iconos SHA-256 antes de activar la nueva instantánea.
Los XML de idioma siguen dentro del AAB (`enableSplit=false`).

## Consultar y descargar

El botón de cabecera tiene texto, tanto en Formatos como en Servidores VPN.
Una consulta devuelve solo el número de versión; si es más nuevo, muestra
un aviso para confirmar la descarga. **No hay URLs de descarga en los botones**.
Durante la descarga, Android muestra actividad y el porcentaje de
**fichas e iconos procesados y validados** (no bytes transferidos). Solo se
muestra 100 % tras guardar la instantánea cifrada.

La consulta de versiones funciona al reabrir la aplicación aunque una
notificación haya llegado mientras estaba cerrada o desconectada. En primer
plano, una vigilancia HTTPS de versiones puede avisar de cambios; opcionalmente
WorkManager comprueba cada 24 horas en segundo plano y almacena solamente
la versión pendiente. No se usa FCM ni se mantienen sockets permanentes al
cerrar la app; **no es una notificación push instantánea con el proceso cerrado**.
El usuario confirma la descarga. La preferencia de sincronización automática
controla solo el trabajo de recuperación en segundo plano.

## Clasificación de avisos

- Extensión no incluida en el catálogo → archivo no compatible / sugerir
  integración; nunca enviar sus bytes al worker.
- Texto sin prefijo o reconocimiento compatible → texto no compatible.
- Prefijo/extensión conocida pero versión/método explícitamente no soportado →
  versión no compatible. `DECODE_FAILED` es ambiguo (también puede ser
  archivo alterado o corrupto); el aviso no debe presentarse como prueba de
  que la aplicación del proveedor ha cambiado sus claves.
- Contraseña errónea y protección de clave pública permanecen en sus propios
  casos, sin confundirse con una incompatibilidad general.
- El sistema de métricas distingue avisos esperados de fallos operativos:
  incompatibilidades y descifrado ambiguo de archivos/textos se registran
  como advertencias, sin incrementar las incidencias de infraestructura.
  No se conservan archivos ni resultados descifrados en la telemetría.

## Avisos de actualización de la aplicación

`/api/v1/whats-new` puede incluir `appUpdate:{versionCode,versionName}`
cuando el servidor fija **ambas** variables de entorno:

```text
CLOUD_ANDROID_LATEST_VERSION_CODE=31
CLOUD_ANDROID_LATEST_VERSION_NAME=1.1.20
```

**NO configurarlas ni activarlas antes de que la actualización esté
realmente publicada.** Si el código remoto supera el instalado y no fue
descartado anteriormente, la app ofrece «Abrir Telegram» o «Cerrar».
Telegram es un destino fijo permitido dentro del APK:
`https://t.me/GhostDeve`. El servidor no puede reemplazarlo con
redirecciones ni URLs suministradas por terceros. Se conserva la
localización de interfaz en los 14 idiomas.

## Límites de esta fase

Solo el APK nuevo podrá usar las nuevas superficies y avisos; añadir un
descifrador nuevo al VPS no elimina la necesidad de publicar nuevas versiones
del APK cuando cambien el protocolo de transporte, la autenticación, las
dependencias nativas o el diseño. Los decodificadores Cloud y su seguridad
siguen siendo responsabilidad del servidor. Las pruebas CI no sustituyen
la instalación del AAB en Google Play y la comprobación física de sus
14 idiomas, la red y el almacenamiento.
