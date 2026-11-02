# Compatibilidad administrable y solicitudes Android

Implementación del 2 de noviembre de 2026 en `fix/http-jireh-current-method`.

## Política inicial y controles del panel V2

El perfil inicial de Play Integrity pasa a **Observar sin bloquear**, permanente. La licencia de Play, la integridad fuerte, el SDK informado, Play Protect, riesgos de acceso y la comprobación de Play por operación son controles independientes. También puede desactivarse la consulta a Google. En modo Exigir, la identidad y firma reconocidas por Google siguen siendo obligatorias; seleccionar integridad básica no vuelve reconocida una APK externa.

El perfil de hardware observa parches y arranque de forma predeterminada. Permite exigirlos por separado, elegir 12, 18, 24, 36 o 48 meses de antigüedad y guardar el perfil permanentemente o durante 1, 6, 24 o 48 horas. Al vencer un perfil temporal se vuelve a observar ambas señales.

No se desactivan las raíces de confianza, revocaciones, desafío, identidad y certificado de la APK, nivel de hardware, firma de solicitudes ni HPKE. Un dispositivo con root o bootloader abierto puede seguir fallando si no presenta una cadena auténtica admitida. No se inventa un indicador de root: aparece como **desconocido**.

Los documentos persistentes `v2-play-integrity.json` y `v2-device-admission.json` migran una sola vez del esquema JSON 1 al 2, con aumento de revisión y los perfiles compatibles solicitados. Esto no modifica la política independiente de API V1. Se conservan archivos dañados como error de configuración; no se interpreta un JSON inválido como autorización.

Guardar una política invalida sesiones anteriores. Cambiar el perfil de hardware exige nueva atestación de las claves. La política permanente se transmite al verificador privado mediante una autorización interna breve, sin exponerla al cliente.

## Diagnóstico

El panel distingue intentos aceptados, rechazados y señales observadas. Los contadores de hardware abarcan desde el arranque del verificador; los de admisión V2 corresponden al día UTC. Un teléfono puede generar varios intentos y una clave registrada puede reutilizarse sin otra verificación de certificados. Ninguno de estos contadores equivale a usuarios únicos ni demuestra el porcentaje de teléfonos afectados.

Los parches opcionales ausentes y el SDK no informado se muestran como desconocidos. `CERT_PATH` conserva detalles técnicos acotados, separados de las observaciones. Si el servicio antiguo no informa aceptaciones, el denominador y la tasa se presentan como desconocidos, no como cero. No se registran tokens, claves, certificados, IP, enlaces privados ni contenidos descifrados en estas métricas.

La consulta al servicio privado tiene límite de tamaño y tiempo. Los fallos de telemetría no cambian las decisiones de autenticación.

## Solicitudes desde la APK nueva

Con una sesión vigente:

| Acción | Peticiones al VPS |
| --- | ---: |
| Cambiar a Formatos o Server VPN | 0 |
| Confirmar descarga o actualización del catálogo | 1 |
| Descifrar archivo, texto o catálogo de un proveedor | 1 |
| Importar y descifrar referencia HTTP Custom sin credenciales adicionales | 1 |

El catálogo incluye formatos y todos los iconos originales en una respuesta cifrada; se comprueba cada SHA-256 antes de guardar. Se admite hasta 32 MiB de catálogo y 48 MiB de respuesta de transporte de catálogo. Los iconos individuales conservan su límite independiente. No se realizan peticiones adicionales por cada icono.

Play por operación puede seguir exigiéndose: el token Standard se vincula al bearer emitido por el servidor, operación y bytes cifrados exactos. La APK calcula esa vinculación sin pedir un desafío adicional al VPS. Se mantienen PoP, consumo único del identificador y protección de repetición. Los clientes antiguos conservan su protocolo previo.

Las sesiones nuevas duran 30 minutos por defecto, configurables entre 5 minutos y una hora; los clientes antiguos reciben como máximo 5 minutos. La autenticación inicial o al vencer la sesión conserva sus dos intercambios de desafío y sesión: son adicionales a la operación y no se ocultan en el conteo anterior.

Se eliminan la consulta del catálogo antes de pedir exportación compatible y el segundo descifrado de un HC que ya tuvo éxito al comprobar sus requisitos. Ese resultado se conserva solo una vez en RAM durante hasta 60 segundos.

Si un archivo requiere contraseña o ID, el intento posterior con datos aportados por el usuario es otra operación necesaria. En referencias HTTP Custom, el servidor descarga una vez y devuelve el archivo aún cifrado únicamente si hace falta abrir ese diálogo; no se vuelve a descargar un enlace de un solo uso ni se guarda el archivo en el servidor.

La observación visible del catálogo lee avisos locales. La recuperación de versiones en segundo plano sigue siendo voluntaria, diaria, sin ráfagas de reintentos. Novedades y versión de la APK comparten una consulta, con intervalo de seis horas y espera de quince minutos tras un intento fallido.

## Actualización y validación

Actualizar primero el servidor desde esta rama y reconstruir **web** y **key-attestation** siguiendo el flujo de actualización del proyecto. Conservar `cloud.env`, volúmenes y claves HPKE; no generar ni rotar claves como parte de esta actualización. Después compilar y distribuir la APK nueva para activar las mejoras del cliente. Actualizar solo el VPS no puede eliminar las solicitudes de una APK antigua.

Verificar el modo Observar, los dos controles de hardware y el diagnóstico en el panel. Probar una descarga con la caché vacía y otra con la versión vigente; confirmar con contadores de acceso que la navegación no genera solicitudes del catálogo. Probar un archivo sencillo y otro que requiera credenciales. Validar dispositivos reales con y sin Google Play, distintos parches y bootloader abierto antes de exigir señales.

Las pruebas de código cubren admisión, configuración administrativa con sesión/CSRF/revisión, fallos de Google, replay, HPKE, catálogo con iconos, tamaño superior a 4 MiB y ambos protocolos HTTP Custom. El verificador se prueba con cadenas sintéticas firmadas; esto no sustituye la matriz de teléfonos reales.

## Comprobación realizada

- 66 pruebas Node aprobadas en los grupos de seguridad, panel, métricas, catálogo, HPKE e importación HTTP Custom.
- 10 pruebas del verificador Kotlin aprobadas con cadenas sintéticas firmadas.
- Compilación `:app:compileReleaseKotlin` aprobada, con recursos y manifiesto de Cloud.
- Biblioteca nativa compilada con NDK 27 para ARM64 y Android 24.
- Contratos de sesión y concurrencia, 27 descriptores JNI, interoperabilidad de catálogo y coincidencia del hash de acción entre C++ y Node aprobados. También se probó un catálogo sintético de más de 4 MiB.

No se realizó despliegue en el VPS, publicación de APK/AAB ni prueba en teléfonos físicos. Las advertencias de compilación observadas corresponden a APIs obsoletas ya existentes.
