# C14 — Observabilidad avanzada sin datos personales

## Alcance

Agregar al panel administrativo siete herramientas: comparación antes/después de reinicios, histogramas de latencia por motor/proveedor, causas técnicas, alertas por proveedores, versiones agregadas, salud operacional y auditoría de acciones de administración. El trabajo permanece en la rama del PR #96; no desplegar ni publicar sin revisión.

## 1. Comparación antes y después

El reinicio de errores C13 guarda un snapshot por formato y fecha UTC con **fallidos**, **intentos**, **correctos** y códigos de error. El panel calcula tasas antes/después con contadores agregados del mismo período retenido (hasta siete días); si faltan denominadores no calcula porcentajes. Conservar datos originales de éxito, bytes y uso. Los reinicios repetidos reemplazan el punto de referencia. No inferir precisión histórica fuera del rango de retención.

## 2. Rendimiento y diagnóstico de motor

En los gateways de archivo/texto, HTTP Injector y Server VPN se toma `performance.now()` alrededor de la llamada efectiva al worker (y de la descarga remota para los proveedores). Solo se envía a Redis un **rango de duración** y suma/conteo por formato/servicio. No se guarda una muestra individual ni el cuerpo de la solicitud o respuesta. El P95 mostrado es un **límite superior de histograma**, no un percentil exacto; la media se redondea en milisegundos. Las llamadas previas al despliegue no pueden reconstruirse.

Categorías cerradas: `network`, `timeout`, `engine`, `response`, `compatibility` y `other`. Los errores de usuario sin descifrado no generan telemetría operativa. Los códigos y formatos se sanitizan antes de usarse como etiquetas Redis.

## 3. Alertas automáticas de proveedores

Solo dentro del panel: se registra un aviso si las últimas tres operaciones de un proveedor fallan por conexión o timeout, o si al menos cinco de sus diez últimas operaciones son errores reales. Advertencias de incompatibilidad no cuentan como caída del servicio. Máximo un aviso por tipo/proveedor durante 60 minutos (Redis `SET NX EX`). Las alertas caducan a los ocho días y no envían correos, Telegram, notificaciones push ni información a terceros. Este monitor es **reactivo**: si no hay solicitudes nuevas no puede detectar que un proveedor esté caído; para disponibilidad proactiva hace falta una verificación sintética explícita.

## 4. Versiones agregadas

Android Cloud envía `X-SPDecode-App-Version` desde `BuildConfig.VERSION_NAME` a través de la capa HTTPS nativa existente. Se acepta solo una versión numérica acotada, nunca identificadores de usuario. Las apps ya instaladas que no envían esa cabecera aparecen como `not-provided`; para tener cobertura real se necesita **una futura actualización Android**. Una cabecera informativa no equivale a prueba de integridad. Para el formato `.rt`, se identifica el encabezado `RSE1` a `RSE5` leyendo solo los primeros cuatro bytes ya recibidos y sin guardarlos; el resto de extensiones no muestra versión hasta que exista metadato confiable del motor. No confundir la versión del catálogo general con la versión del archivo exportado.

## 5. Salud del servidor

Sin agente de host adicional, el panel puede observar salud de Redis/worker y recursos del contenedor web vía cgroups (memoria y uso de CPU desde la lectura anterior). **No son métricas del host VPS completo.** El backend actual limita concurrencia por sesión y no dispone de cola persistente: la sección de cola indica esa condición en vez de mostrar un número inventado. Para CPU/RAM reales del VPS, contenedores adicionales y cola global futura se requerirá un agente de métricas interno protegido, expresamente desplegado en host y sin exposición pública.

## 6. Auditoría de administración

Cada reinicio C13 de errores registra únicamente `at`, `action=reset_errors`, `scope`, `format` (si aplica) y `formatsReset`. Sin IP, nombre de administrador, token de sesión, archivos, contraseñas ni información de usuarios. Lista acotada a cien elementos, TTL ocho días, disponible solo para el administrador autenticado.

## 7. Contrato y seguridad

- Redis almacena un hash agregado por fecha `spc14:obs:YYYY-MM-DD` con TTL 8 días, listas breves por proveedor, hasta cien alertas/acciones y claves de cooldown de una hora.
- `GET /api/admin/observability?days=1|7` requiere la cookie de sesión del administrador, no acepta otros parámetros y responde con `Cache-Control: private, no-store`.
- El endpoint no modifica mantenimiento, Play Integrity, credenciales, catálogos ni configuraciones de los decodificadores.
- La instrumentación es mejor esfuerzo: si Redis falla, el resultado de descifrado al usuario no se altera.
- Cobertura: pruebas Node `cloud/web/tests/c14-observability.test.mjs`, pruebas React/Next en C6, Kotlin/C++ Android en C4, y pruebas Python de `.rt` incluyendo banner variable y nodos anidados.

## 8. REESE TUNNEL .rt

El lector canónico `decoders/Python/apps/REESE_TUNNEL/reese_tunnel.py` elimina **la clave JSON exacta** `bannerImage` de diccionarios en cualquier nivel después de validar el documento (no compara ni guarda su valor). Esto elimina la imagen tanto del texto serializado como del JSON estructurado devuelto por Cloud. No elimina otras claves como `BannerImage` o `bannerImageUrl`. Las pruebas de equivalencia conservan los vectores originales cifrados y solo adaptan los campos esperados del resultado. Es un cambio de backend; no necesita recompilar Android para eliminar el banner del resultado Cloud.

## 9. Despliegue

No fusionar a main ni actualizar el VPS automáticamente. Validar CI, después desplegar web/worker de forma controlada, revisar sesión administrativa y simular alertas con datos de pruebas. Las métricas comienzan desde el despliegue; no se reinterpreta el histórico. Si más adelante se desea aprovechar el nuevo encabezado `X-SPDecode-App-Version` en instalaciones de Play, generar un AAB con **nuevo** versionCode (el 27 ya se publicó) tras las pruebas específicas de Android; no reutilizar un versionCode cargado en Play Console.
