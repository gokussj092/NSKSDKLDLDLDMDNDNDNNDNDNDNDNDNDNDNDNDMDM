# SP-DECODE — Directorio Server VPN V2: descargas reanudables, progreso real y versiones correctas

**Fecha de diseño:** 2026-11-04 (hora local del proyecto). **Rama:** `feat/nuevas-integraciones`.  
**Estado:** ESPECIFICACIÓN APROBABLE / PENDIENTE DE IMPLEMENTACIÓN. **Este commit solo documenta; no despliega VPS, no cambia código ejecutable, no altera la APK 1.1.27 (build 42) ni inicia un build.**

> **CORRECCIÓN DE ALCANCE (aclaración del propietario, 2026-11-04):** el crash por resultados JSON extensos de **más de 8,000 líneas** ocurre al **visualizar/procesar resultados de descifrado de configuraciones VPN**, NO al descargar o cargar el inventario de apps Server VPN. La investigación, motor `libspdecode_result_engine.so`, virtualización del visor y QA de esos resultados están definidos exclusivamente en [Resultados de descifrado extensos: motor nativo y visor incremental](../../docs/android/RESULTADOS_DESCIFRADOS_JSON_GRANDES_MOTOR_NATIVO_2026_11_04.md). Este plan se limita a **descarga, caché, manifest, metadata e iconos del directorio de aplicaciones Server VPN**.

## 0. Propósito y criterios obligatorios

Corregir de raíz las descargas del directorio de aplicaciones Server VPN que se interrumpen, fallan cerca de los 8 MB o son inestables en redes lentas. Hacer el sistema escalable para más aplicaciones, iconos originales y formatos, sin mezclar esta mejora con los resultados descifrados de miles de líneas. Conservar el diseño AMOLED modal aprobado y mostrar **bytes reales descargados / bytes reales por descargar**, la barra proporcional y una **versión visible del catálogo** correcta (distinta de la versión técnica de sincronización).

**Requisitos innegociables:**
- Descarga **reanudable por fragmentos verificados**; al fallar el tramo N, NO volver a descargar lo ya validado si el mismo snapshot sigue disponible.
- Progreso **determinista basado en tamaños autenticados**, sin porcentaje estimado por tiempo y sin 100 % antes de que el snapshot esté validado y activado.
- Mostrar el tamaño total verdadero y lo recibido bajo una unidad coherente, distinguiendo tamaño lógico total del catálogo de **datos pendientes de transferir**; no inventar totales cuando falte manifiesto válido.
- No acumular catálogo, iconos, JSON expandido, bitmap y objetos Kotlin completos en RAM simultáneamente.
- Ingestión/validación/lectura de **metadatos del directorio de apps** con límites de memoria y JNI acotado; una biblioteca `.so` exclusiva para el directorio es **opcional y separada**. El motor nativo `.so` específicamente solicitado para el crash de **resultados descifrados** se diseña en el documento de resultados citado arriba. No mover descifradores de proveedores al cliente.
- Separar versión de presentación (ejemplo declarado por propietario: **13**, pendiente de fuente de verdad) de la revisión técnica interna (ejemplo observado en UI: **2738494**). No rebajar, falsificar, poner a cero ni reutilizar la versión interna del protocolo C10/C12.
- Cache cifrada (Android Keystore AES-GCM), validación autenticada, hash por objeto, staging y confirmación atómica; siempre preservar el último catálogo completo y compatible.
- Mantener compatibilidad con APK anteriores usando el contrato existente mientras se despliega el nuevo protocolo; no forzar descargas imposibles ni eliminar el endpoint anterior.
- Acceso solo por rutas fijas de SP-DECODE y autorización Cloud V2/HPKE/atestación actual; nunca URL arbitraria del manifiesto o del usuario.
- Respetar descarga lenta: no hay plazo global de 60 s; temporizadores solo de conexión/inactividad y un presupuesto por fragmento coherente con la red, sujetos a Nginx, proxy y carga real.
- La versión offline de la aplicación y el asset local `decoder_catalog.json` no se modifican como parte de este plan; los formatos importados desde WhatsApp/Telegram siguen detectándose desde el último snapshot verificado.

## 1. Hallazgos auditados en la rama (NO diagnóstico definitivo de producción)

Fuentes exactas:
- `android/app/src/main/cpp/spdecode_transport.cpp`: operación 10; `kCatalogIdleTimeoutMs=60000` (inactividad **por lectura**); `replyCap=48 MiB` para catálogo, flujo actual en una sola respuesta; callback con bytes HTTP y `getContentLengthLong()`. Si el proxy omite Content-Length, total=-1.
- `android/app/src/main/java/com/ghostdeveloper/spdecode/CatalogTransferDialog.kt`: muestra porcentaje y barra proporcional **solo** cuando `totalBytes>0`; si no, barra indeterminada y «X MB descargados». La captura del propietario muestra 4.76 MB y sin tamaño total.
- `android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/CloudDecodeClient.kt`: `MAX_INPUT=8 MiB` corresponde a **archivos subidos para descifrar**, NO al límite de bajada del catálogo.
- `android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/CatalogEnvelope.kt`: recibe sobre criptográfico, descomprime mediante `GZIPInputStream` a `ByteArrayOutputStream`, crea `String` completa y `JSONObject` completo; `MAX_PLAIN=32 MiB`.
- `android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/ServerVpnCatalogRepository.kt`: comprueba todos los iconos y construye bitmaps/objetos; el catálogo se guarda cifrado al final, pero la ingestión todavía usa múltiples representaciones del JSON e iconos en memoria.
- `android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/ServerVpnSecureCache.kt`: cifrado AES-256-GCM con Android Keystore y compresión; límite actual **6 MiB por registro** y atomicidad de escritura por archivo, no por conjunto de snapshot.
- `cloud/web/app/api/v1/server-vpn/catalog/route.js`: si recibe `X-SPDecode-Catalog-Bundle: 1`, inserta **todos los iconos originales en Base64** dentro de la respuesta JSON. `cloud/web/lib/catalog-envelope.mjs` comprime y cifra un JSON con límite 32 MiB descomprimidos.
- `cloud/web/lib/v2-transport.mjs`: respuesta protegida HPKE acotada a 96 MiB; la respuesta HTTP cifrada no proporciona necesariamente Content-Length; puede requerir materializar contenido para sellado.
- `cloud/infra/vps/nginx-config.py`: proxy V2 actual usa `proxy_read_timeout 155s`; ese valor NO equivale a permitir reanudar bajadas ni garantiza que el servidor desplegado tenga esa configuración.
- Inventario de la rama: 66 archivos PNG en `cloud/web/public/server-vpn-icons/` ocupan ~**4.90 MiB** originales (antes de Base64, JSON, cifrado y transporte).
- `cloud/web/lib/c12-provider-controls.mjs`: el catálogo técnico evoluciona con huellas y contador **monótono** almacenado en el volumen persistente; `CATALOG_VERSION` de código es un mínimo, no el número editorial de versiones.

**Atención:** que una descarga falle cerca de «8 MB» NO demuestra que el cliente tenga un límite de 8 MB. Tampoco está probado que los cierres sean `OutOfMemoryError`: pueden ser excepciones de parseo, límites de caché, validación, errores del servidor o incompatibilidad del contrato. Esta especificación obliga a obtener evidencia real antes de elegir un hotfix.

## 2. Fase de diagnóstico obligatoria: localizar la falla real

Antes de reemplazar el protocolo, registrar sin exponer datos privados:
1. Versión instalada de APK, versión de protocolo, revisionId del servidor, `operation=10`, tamaño HTTP anunciado (si existe), bytes HTTP recibidos al fallar, estado HTTP, tiempo de conexión y tiempo de inactividad.
2. Separar hitos: solicitud autenticada → respuesta → lectura completa → HPKE autenticado → envelope autenticado → GZIP descomprimido → parseo JSON → validaciones de formatos/apps/iconos → escritura de objetos → confirmación de snapshot → render UI.
3. Etiquetar las excepciones en familias estables: `CATALOG_NETWORK_INTERRUPTED`, `CATALOG_TRANSFER_TRUNCATED`, `CATALOG_HTTP_REJECTED`, `CATALOG_AUTH_FAILED`, `CATALOG_SCHEMA_INVALID`, `CATALOG_OBJECT_HASH_MISMATCH`, `CATALOG_MEMORY_LIMIT`, `CATALOG_CACHE_FAILED`, `CATALOG_VERSION_CONFLICT`, `CATALOG_CANCELLED`; mapear los códigos anteriores. No loguear tokens, claves, URL de proveedores, contenidos cifrados completos ni JSON confidencial.
4. Instrumentar picos de memoria Java/Native, bitmap heap, GC, `OutOfMemoryError` y crash nativo (`SIGABRT/SIGSEGV`), disco libre y bytes descomprimidos, con dispositivos reales lentos.
5. Probar un catálogo real de producción y el servidor efectivamente desplegado, no solo los archivos de GitHub; revisar reglas actuales de Nginx, logs web, versiones de contenedor y respuesta HPKE autenticada.
6. Identificar si el valor mostrado como versión procede de `catalogVersion`, `activeCatalogVersion`, override `CLOUD_SERVER_VPN_CATALOG_VERSION`, contador persistente C12 o campo distinto.
7. Comparar catálogo remoto actual con `knownVersion=0`, `unchanged`, `watch`, `iconBundle`, `formatCount`, `textCount`, `compatibleExports` y SHA-256 de iconos.

**Gate D0:** documento de evidencia reproducible (qué falló, en qué fase, con bytes, HTTP status y stack o código) antes de declarar solucionado el fallo original. Si existe un defecto puntual que puede corregirse sin nueva arquitectura, priorizarlo como parche compatible, sin postergar la arquitectura escalable.

## 3. Arquitectura objetivo: manifiesto + objetos independientes

### 3.1. Separar contenido

El catálogo deja de ser necesariamente un gran JSON con todas las imágenes embebidas:
- **`metadata.json` compacto:** apps, IDs, nombres, capacidades, estados, revisiones de método, formatos/extensiones, textos/referencias y lista de iconos identificados por hash. **Jamás** scripts de descifrado ni credenciales de servidores.
- **Iconos `<sha256>.png` individuales:** mantener los PNG originales y sus hashes; descargar solo si no existen en la cache cifrada local con el mismo hash. Decodificar bitmaps de forma diferida para las tarjetas visibles (paginación o lazy list).
- **`manifest` autenticado:** snapshot inmutable, revisiones internas y visibles, esquema, objetos, hashes, tamaños de cada objeto y chunks. El catálogo técnico puede crecer sin forzar al Android a almacenar una sola respuesta gigantesca en memoria.
- **Cache versionada:** metadatos cifrados en formato estructurado compacto + iconos cifrados content-addressed, no JSON enorme duplicado. Snapshot anterior permanece activo hasta confirmar el nuevo.

Evitar regenerar el paquete completo por cada consulta: el backend prepara artefactos inmutables **cuando se publica** un nuevo snapshot, conserva su manifiesto y expone chunks verificables. No serializar/comprimir/cifrar 60+ PNG por cada solicitud de usuario. Un manifest nuevo referencia los hashes de iconos que no cambian.

### 3.2. Reutilización de recursos

Si un snapshot nuevo cambia solo 2 de 66 iconos, el cliente descargará únicamente los 2 nuevos, junto con los metadatos que cambiaron; no descargará 64 PNG idénticos. La pantalla indicará **«Datos por descargar: X MiB»** según el snapshot comparado con cache, no el peso lógico completo del catálogo si ambos son distintos.

La deduplicación se basa en hashes del servidor **verificados** localmente, nunca en nombres de archivo ni tamaños sin hash.

## 4. Contrato futuro del protocolo resumible — propuesta, NO endpoints existentes

**Negociación**: usar una capacidad versionada `catalog-chunks-v1` en una ruta/operación nueva aprobada en `v2-routes.mjs` y en C++ (NO asumir que un número de operación está libre). El servidor mantiene la operación **10** como contrato legacy V2 y la API V1 para clientes ya publicados. El primer despliegue será compatible con ambos.

### 4.1. Solicitud de manifiesto

Solicitud autenticada con sesión válida, estado del snapshot cacheado, versión soportada y protocolo admitido. Respuesta **HPKE-autenticada** con campos lógicos (ejemplo ilustrativo, NO JSON ejecutable):

- `protocol: catalog-chunks-v1`, `schemaVersion`, `snapshotId` único no adivinable/reutilizado y/o hash canónico estable.
- `catalogVersion`: entero monótono **interno** que siguen usando C10/C12/Android antiguos.
- `displayVersion`: versión editorial para mostrar al usuario, controlada desde panel/flujo de publicación y verificada.
- `manifestHash`, `createdAt`, `validUntil`, `totalLogicalBytes`, `totalTransferBytes` si está definido en contrato autenticado, `objects[]` con `type`, `sha256`, `byteLength`, `chunkSize`, `chunkCount` y hashes de cada chunk.
- `compatibleExports`, `formats`, `textFormats`, `onlineReferences` siguen siendo metadatos, sin romper los validadores de capacidades existentes.

**Tamaño total real**: el servidor publica conteos en el manifiesto, autenticados y calculados sobre una representación específica e inmutable. Diferenciar expresamente:
1. `totalLogicalBytes` = suma de tamaños originales de metadata + iconos del snapshot.
2. `bytesToDownload` = suma exacta de bytes de los objetos/chunks **pendientes** (excluye los ya cacheados y autenticados).
3. `bytesDownloaded` = bytes de carga útil recibidos y verificados para esta descarga más los chunks recuperados del mismo snapshot, nunca «bytes estimados».

Si el UI muestra tamaño **transferido por red**, debe utilizar una base definida del protocolo y contabilizar overhead HPKE exacto; si se usa bytes de payload, rotular «Datos del catálogo» en lugar de afirmar «tráfico HTTP total». La suma/porcentaje y el contador deben usar la **misma unidad y base**. Un `Content-Length` ausente NO justifica inventar un total; el manifest autenticado nuevo sí permite conocer el tamaño objetivo.

### 4.2. Descargas de chunks

**Parámetros iniciales propuestos para benchmarking**: 256 KiB de payload por fragmento (configurable tras pruebas, por ejemplo 128–512 KiB); nunca confundir tamaño de fragmento con tamaño total. A 100 kbps esta granularidad reduce el costo de un reintento completo. Elegir límite final por mediciones de CPU, red y proxy, no por un número arbitrario.

Para cada chunk:
- Cliente pide `snapshotId`, `objectHash`, `chunkIndex` y opcional `manifestHash` desde **rutas fijas**. El servidor responde exactamente con la porción publicada, no recalcula otra versión ni acepta rangos arbitrarios fuera del manifiesto.
- Cada respuesta debe estar **autenticada de forma independiente** (HPKE + AAD/vinculación a snapshot, objeto, índice, longitud y solicitud); hash del chunk, hash final del objeto y hash del manifest se comprueban antes de activar. Nunca reutilizar nonce/clave o guardar una respuesta vieja como si perteneciera a otro snapshot.
- Fragments confirmados se guardan en staging **cifrado en reposo**, con estado/journal transaccional y metadatos de reanudación. No guardar bloques abiertos en un JSON/archivo temporal en texto plano. Reiniciar sesión de Play/HPKE permite volver a solicitar el mismo chunk del snapshot, no reutilizar contexto criptográfico expirado.
- Reintentar con backoff exponencial acotado y jitter por errores transitorios (red/5xx/429), respetar `Retry-After`. Fallas de integridad, autorización o esquema NO se «reintentan hasta que funcionen» indefinidamente.
- Si se interrumpe la red, el proceso o el teléfono, continuar desde el **primer fragmento faltante** del mismo snapshot verificado. Si el servidor ya retiró ese snapshot, se negocia el más reciente; se reutilizan objetos por SHA-256 únicamente si son idénticos; si no, se descartan los fragmentos incompatibles.
- Evitar un conjunto de millones de chunks en RAM: manifiestos paginados/bounded, estados compactos, índices y límites máximos por versión/objeto/sesión. Imponer cuotas de almacenamiento y TTL, con limpieza de staging expirado.
- Al pulsar **Cancelar**, cerrar inmediatamente la transferencia y descartar contexto criptográfico de esa solicitud. Por defecto se podrán conservar los chunks **ya autenticados y cifrados** durante una ventana de reanudación definida, informándolo en interfaz/privacidad; un control «Eliminar descarga parcial» y la revocación de consentimiento borran ese estado. No conservar partes sin consentimiento.

### 4.3. Estados y confirmación

`NO_CACHE → CHECKING → MANIFEST_READY → DOWNLOADING → VERIFYING → COMMITTING → READY`.

Alternativas `PAUSED_NETWORK`, `CANCELLED`, `RETRY_WAIT`, `FAILED_RETRYABLE`, `FAILED_FATAL`, `ROLLBACK`.

**Regla de éxito**: no mostrar «Catálogo actualizado» hasta que 100 % de los chunks requeridos estén autenticados, los objetos finales pasen SHA-256, el motor nativo valide el catálogo y todas las referencias, el cache cifrado sea consistente y se active un puntero a snapshot de forma **atómica**. El 100 % de descarga únicamente inicia «Verificando y guardando…»; no es por sí solo éxito del catálogo.

### 4.4. Compatibilidad y migración

- El servidor primero: nuevos manifest/chunks opcionales bajo feature flag y autorización, sin alterar la respuesta legacy para APK 1.1.27 ni V1.
- APK futura: negocia `catalog-chunks-v1`, migra cache compatible sin perder imágenes, cae a operación 10 **solo si** el servidor no soporta la nueva capacidad y el tamaño legacy está dentro de límites seguros. Nunca suprimir fallos de autenticación mediante downgrade a HTTP inseguro.
- Versiones antiguas siguen recibiendo su respuesta compatible por un período definido. Conservar control de versiones/capabilities para evitar activación masiva de un payload que exceda las capacidades legacy.
- Si los iconos superan los límites legacy, el servidor debe poder ofrecer un snapshot legacy compatible, no romper en silencio a usuarios antiguos; documentar periodo de soporte y telemetría agregada.
- Diferenciar «el servidor no admite v2» de «la respuesta v2 está alterada»: solo el primero permite fallback.

## 5. Lectura eficiente del inventario Server VPN (NO los resultados descifrados)

**Corrección:** esta sección solo describe el JSON de metadatos e iconos del directorio Server VPN. **No investiga ni resuelve** cierres al mostrar catálogos **descifrados de configuraciones VPN** con más de 8,000 líneas. Para ello se elaboró `docs/android/RESULTADOS_DESCIFRADOS_JSON_GRANDES_MOTOR_NATIVO_2026_11_04.md` y se propone `libspdecode_result_engine.so` junto con `LazyColumn` de filas virtualizadas. Son proyectos distintos.

### 5.1. Objetivo del directorio

- El nuevo manifest ofrece metadatos compactos y referencias a iconos por hash; evitar embebido Base64 y procesamiento de todas las imágenes en una sola respuesta.
- Mantener límites de profundidad, cardinalidad, bytes, UTF-8, duplicados y referencias válidas para `formats`, `apps`, `iconBundle` legacy y `compatibleExports`.
- Procesar metadata de forma acotada fuera del hilo principal; no crear cientos de bitmaps al arrancar; mostrar solo tarjetas visibles con carga diferida.
- No alterar métodos de descifrado Cloud ni los resultados (texto/JSON) que devuelve cada proveedor.

### 5.2. ¿Se requiere un `.so` exclusivo para el directorio?

**No automáticamente.** Primero probar la nueva transferencia por objetos y el parseo de metadata. Si sigue habiendo picos de memoria, evaluar un parser C++ SAX/JNI ligero **solo para el inventario**. Un eventual `libspdecode_catalog_engine.so` será **opcional, con decisión por mediciones**, independiente de `libspdecode_result_engine.so` que atiende el problema de resultados.

La protección de memoria y consistencia del directorio sí sigue siendo obligatoria:
- Cotas de tamaño y descompresión, validación de esquema y hashes por objeto.
- Cache cifrada Android Keystore sin llaves embebidas, staging, commit atómico y rollback.
- Imágenes bajo demanda y liberación de recursos ante cancelación/error.
- QA en dispositivos con poca RAM, lista creciente de aplicaciones y fallos de snapshot.

### 5.3. Criterio de aceptación específico

El directorio de apps puede actualizarse y navegarse con los iconos originales sin descargar objetos no modificados ni exponer un JSON grande de iconos a Compose. **La ausencia de crash al mostrar 8,000 líneas descifradas no se valida con esta prueba**, sino con el plan de resultados.

## 6. Progreso UI AMOLED aprobado

Se conserva **el mismo diálogo superpuesto** sobre Servidores VPN o Formatos y el estilo negro AMOLED. No navegar a otra pantalla ni mostrar una pantalla de progreso independiente.

### Estado de descarga con total conocido

    Descargando catálogo
    [────────────████████████────────────]     68 %
    4.76 MiB / 7.00 MiB
    [Cancelar]

La maqueta es **ilustrativa**: el porcentaje y tamaño reales vienen del manifiesto autenticado y los chunks, no son valores fijos. El relleno de barra debe aumentar monotónicamente con los **bytes verificados**, no animarse sin relación con la bajada. Mantener buen contraste (puede ser azul aprobado o color de marca accesible) y bordes discretos, no un marco blanco dominante.

### Progreso y recuperación

- Sin manifiesto todavía: «Preparando descarga…», progreso indeterminado; **no** inventar tamaño.
- Con manifiesto validado: mostrar `descargados / por descargar`, porcentaje real del mismo conjunto de datos, sin estimación de tiempo obligatoria.
- Cuando ya existen iconos de la cache: aclarar «X MiB pendientes» y, opcionalmente en detalles, «Tamaño total del catálogo Y MiB»; no aparentar que «el catálogo solo pesa X» si Y incluye iconos cacheados.
- Error de red: «Conexión interrumpida. Se conservaron N MiB verificados» y acción **«Reanudar»**. No borrar el catálogo anterior ni mostrar falsamente «archivo no compatible».
- Al completar bytes: «Verificando catálogo…» y «Guardando…», conservando datos; solo entonces éxito.
- Éxito: «Catálogo actualizado» / «Todos los formatos se han guardado» / botón **«Finalizar»**, como el diseño previamente aprobado.
- Cancelar detiene la descarga; si guardamos fragmentos autenticados para reanudar, explicarlo de modo breve y permitir eliminarlos.
- Los mensajes de fallo deben distinguir **red**, **servidor**, **archivo inválido**, **memoria insuficiente** y **reanudación disponible**, sin filtrar errores internos ni códigos sensibles.
- Ocultar el texto de error del catálogo vacío detrás del diálogo mientras se está descargando; si no hay cache, mostrar estado contextual, no error anticipado.
- Accesibilidad, TalkBack, tamaño de fuente, pantallas pequeñas, RTL, 14 idiomas existentes; flujo y estados se actualizan en main thread, trabajo pesado siempre fuera.

**Unidad:** preferir MiB (base 1024) por precisión, o usar MB decimal de forma consistente; no mezclar nombres con conversión distinta. Si el diseñador conserva «MB» en pantalla, deberá calcular en MB decimal o documentar claramente el criterio.

## 7. Versionado correcto de catálogo: dos conceptos, no un solo entero

### 7.1. Problema real

El campo actual `catalogVersion` sirve para reconciliación, watch, cache anti-rollback, fingerprint C12 y cambios de disponibilidad/mantenimiento. Por diseño puede mostrar valores muy grandes como **2738494** o mayores. El archivo `cloud/web/lib/server-vpn-catalog.mjs` también tiene su `CATALOG_VERSION` (mínimo técnico de código), que **NO es necesariamente** la edición humana.

El propietario refiere una versión **13** para el catálogo que desea mostrar. Esta cifra debe validarse contra el registro editorial/administrativo actual; **no hardcodear «13»** ni deducirla de los últimos dígitos de un número de sincronización.

### 7.2. Contrato de versión futura

- `catalogVersion` (compatibilidad legacy) o alias `syncRevision`: entero técnico monótono usado por servidor, cliente antiguo, watch, fingerprint, rollback y cache; **no cambiar su semántica ni reducirlo**.
- `displayVersion`: número/etiqueta editorial **visible al usuario**, por ejemplo `13`, con fuente de verdad versionada en estado administrativo/publicación, actualizada cuando corresponda al catálogo humano. No usar timestamps, `versionCode` Android ni contador C12 como etiqueta de UI.
- `schemaVersion` / `protocolVersion`: indican formato de datos y protocolo, no son la revisión visible.
- `methodRevision`: revisión de **cada método de aplicación**, no versión del catálogo.
- `snapshotId`: identidad criptográfica de un paquete de contenido; no es una etiqueta humana.

La UI muestra `Catálogo de servidores VPN · Versión 13` solo si esa es la `displayVersion` **validada, recibida y activada**. Cuando falta o no está disponible, omitir la etiqueta («Catálogo actualizado») en vez de enseñar el valor técnico como si fuera la versión.

### 7.3. Coherencia y persistencia

- Publicar `displayVersion` en catálogo y manifiesto nuevo; en `watch` solo como dato adicional opcional, **nunca** para decidir si se debe actualizar; usa `catalogVersion`.
- Controlar la edición de `displayVersion` en panel con auditoría y validación de avance; la publicación de una edición no puede crear snapshot parcial o devolver un catálogo más antiguo.
- Guardar en la cache cifrada ambas versiones, más `snapshotId`; mostrar la versión del **snapshot activado** y no una edición anunciada pero no descargada.
- Migración de cache antigua: mantiene `catalogVersion` y formatos, y marca `displayVersion` como desconocida hasta obtener el campo verificado; no hacer «v13» sin soporte.
- Probar casos: edición 13 con syncRevision=2738494, modificación de iconos sin regresión de syncRevision, edición 14, rollback bloqueado y `unchanged` con soporte viejo.

## 8. Infraestructura del VPS: límites, costo y operación

**Antes de desplegar**:
- Auditar límites reales Nginx/proxy/Next.js/worker/HPKE, RAM, CPU, disco, reserva y timeouts; la ruta del catálogo es control de metadatos, no la ruta general de decodificación de archivos VPN.
- Implementar backend de **snapshots inmutables preconstruidos** (metadatos + objetos/chunks content-addressed), con retención de versiones para reanudación. Evitar respuesta de iconos Base64 gigantes en la ruta nueva.
- Almacenar objetos por hash **en VPS/almacenamiento autorizado**, no en Redis como blob permanente. Servir únicamente objetos incluidos en manifests autentificados y asociados al usuario/sesión; límites por IP, sesión y objeto.
- Mantener HPKE V2 end-to-end y replay protection; si se usan URLs de descarga, deben ser rutas propias restringidas y criptográficamente vinculadas al manifiesto y sesión, nunca enlaces compartidos o públicos sin control.
- Ajustar Nginx `proxy_read_timeout` y buffering según **tamaño de chunk** y latencias reales; no extender indiscriminadamente el timeout de toda la API. Evitar 502/504 por construir el catálogo en cada request.
- Control de cuota/disco, cachés/CDN solo si conservan confidencialidad/atestado, limpieza/rotación de snapshots, límites anti-abuso y métricas de errores sin registrar material sensible.
- En snapshot nuevo, publicar primero objetos y hashes, después manifiesto, luego aumentar revisión técnica C12/activar `watch`. Si falla publicación, no anunciar catálogo nuevo.
- Nunca borrar `provider-control/switches.json`, claves HPKE persistentes, secret manager ni volúmenes durante actualización. Backup previo; rollback de código con continuidad de snapshot.
- Plan de compatibilidad con versiones previas: conservar endpoint legacy V1/V2 y documentar cuándo deja de admitir nuevas ampliaciones. Las apps viejas no conocen chunks y no pueden beneficiarse de reanudación sin nueva versión Android.

**Costos**: la primera instalación descarga metadatos e iconos; una actualización normal únicamente descarga objetos nuevos. El manifiesto evita repetir el trabajo de comprimir 60+ PNG para cada solicitud; se medirá impacto en CPU, disco, egress y tiempo de primera carga.

## 9. Casos de prueba exigidos y matriz de QA

### 9.1. Conectividad

- 100 kbps real, 50 kbps, 2G/3G degradada, LTE inestable, Wi-Fi público, pérdida de paquetes, latencia variable y desconexiones de varios minutos.
- Interrupción justo antes, durante y después de un chunk, reinicio de aplicación, muerte de proceso, pantalla apagada y cambio de red.
- Reanudar desde último chunk comprobado; verificar con logs de **bytes realmente transferidos** que no se descargó todo de nuevo.
- Manifest sin tamaño/incorrecto, Content-Length ausente, chunk truncado, servidor 429/500/503, proxy 502/504, socket cerrado, sesión expirada.
- Cancelar a mitad; volver y reanudar si la cache parcial todavía es válida; borrar parcial y comprobar que se elimina.
- Actualizar snapshot del servidor mientras se descarga uno antiguo; congelar versión, validar hashes y completar o renegociar sin mezclar versiones.

### 9.2. Memoria y resiliencia

- Dispositivos Android 13, 14, 15 y 16 con baja RAM disponible; catálogos de 50/100/250/500 apps sintéticas autorizadas y iconos de varios tamaños.
- JSON UTF-8 largo, campos límite, cadenas Unicode, anidamiento excesivo, elementos duplicados, enteros fuera de rango y datos maliciosamente comprimidos.
- Parser fuzz en C++, ASAN/UBSAN en tests nativos, prueba de cierre de Activity, cancelación y low-memory killer.
- Verificar pico máximo de memoria Java + Native, ausencia de ANR, no `SIGSEGV` por JSON inválido y que la actividad original siga navegable.
- JSON mayor que el límite permitido debe fallar **de forma controlada** con error específico, no crear OOM; catálogo anterior permanece intacto.
- Verificación del hash del icono original, imagen corrupta, bitmap descomunal, cache local alterada, KeyStore invalidado y falta de espacio en disco.

### 9.3. Seguridad

- Chunk intercambiado entre dos snapshots, mismo índice con bytes distintos, hash corrupto, manifiesto modificado, reply HPKE inválida o sesión de otro usuario.
- Replays, rangos fuera del manifest, demasiados chunks, DOS por miles de objetos, ratio de descompresión extrema, path traversal, archivo con extensión falsa.
- Certificados, nonces HPKE, Play Integrity, tiempo de expirar sesión, descarga por rutas fijas; ningún fallback de HTTP inseguro o bypass por error de red.
- Ningún `secret`, clave privada, proveedor URL o credencial empaquetada en APK/JSON.
- Pruebas de concurrencia entre descarga automática/manual: un solo snapshot activo y staging consistente.

### 9.4. UX y versión

- Barra proporcional llega a 25/50/75/100 % conforme a bytes **verificados**; los MiB coinciden exactamente con manifiesto y con bytes reales de objeto según semántica elegida.
- Cache reutilizada cambia el denominador de «por descargar» sin mentir sobre tamaño lógico total.
- Estado «Verificando y guardando» después de 100 % descargado y antes de éxito final.
- Cancelación, red interrumpida, reanudación, cierre por error manejado y navegación atrás.
- Texto «Catálogo actualizado» solo después del commit cifrado; botón «Finalizar» activo entonces.
- La versión mostrada es `displayVersion` real, mientras `catalogVersion` técnico continúa avanzando y watch/no-downgrade no se rompe.
- Pantallas AMOLED aprobadas, barra visible de contraste accesible, 14 idiomas, TalkBack, orientación y pantallas pequeñas.
- Importar archivos Cloud desde WhatsApp/Telegram/files con cache antigua/vigente y después de reanudar, sin regresión.

**No declarar QA aprobado sin logs reales, capturas, artefactos y pruebas reproducibles.**

## 10. Fases de implementación y dependencias

| Fase | Entrega | Dependencias / gate |
|---|---|---|
| **C-V2-0** | Diagnóstico real de error 8 MB, memoria y respuesta VPS 1.1.27 | Logs/reproducción y causa exacta identificada |
| **C-V2-1** | Modelo de versionado dual: `catalogVersion` interno + `displayVersion` editorial | Fuente editorial aprobada y compatibilidad watch probada |
| **C-V2-2** | Backend snapshots inmutables, manifest, objetos iconográficos separados y chunks autenticados; protocolo negociado | Tests API/HPKE, backcompat V1/V2, política de retención |
| **C-V2-3** | Cliente Android C++: descargas por chunks, verificación, journal cifrado, cancel/reanudar, progreso real y actualización atómica | Test de red a 100 kbps y reanudación tras caída |
| **C-V2-4** | Ingestión eficiente de metadatos Server VPN (parser Kotlin limitado o `.so` del directorio solo si se demuestra necesario) | Límites RAM, paridad de esquema y compatibilidad de snapshots; el crash de resultados se atiende en plan R-0…R-6 independiente |
| **C-V2-5** | UI AMOLED definitiva de progreso, reanudar, estados y versión visible | Capturas y pruebas de accesibilidad en 14 idiomas |
| **C-V2-6** | Integración y despliegue gradual servidor primero, APK después | Pruebas e2e, telemetría, feature flags, rollback seguro |
| **C-V2-7** | Pruebas de regresión 1.1.27, Android nuevos, producción y limpieza de snapshots | Gate de soporte sin pérdida de cache |

Se podrá adelantar un hotfix del error actual si D0 encuentra una causa concreta que afecte a usuarios, **sin confundir hotfix con la finalización de chunks/motor nativo**.

### Orden de puesta en producción recomendado

1. Investigar fallo actual; corregir y probar de forma compatible cualquier bug crítico.
2. Añadir campos de versión visible y endpoints nuevos en el backend detrás de flag; verificar en staging.
3. Generar snapshots y retención; publicar en backend sin cambiar legacy.
4. Integrar y probar motor nativo y descarga resumible en una futura versión Android; no publicar APK antes de pasar gates.
5. Activar por porcentaje controlado; verificar en dispositivos de red lenta y monitorear.
6. Mantener contrato anterior; si aparecen errores, desactivar capability v2, retornar a snapshot anterior sin perder la cache.

## 11. Definition of Done / aceptación del propietario

El cambio SOLO se considera terminado cuando:
- En una red 100 kbps se puede descargar un catálogo mayor que 8 MB sin corte por duración total; si se corta la conexión, se reanuda y **NO repite los chunks completos y verificados**.
- La barra y la etiqueta `X / Y MiB` reflejan exactamente la cantidad de bytes definida y autenticada, muestran total al arrancar la transferencia y nunca avanzan por animación cuando ese total ya se conoce.
- El directorio Server VPN no se cae por metadatos o PNG inválidos; carga de apps tiene límites y conserva snapshot anterior. El crash del **JSON descifrado de 8,000+ líneas** se valida en el plan separado de resultados.
- Si se decide crear una biblioteca nativa separada para metadatos del directorio, se verificarán ABIs, JNI, memoria y páginas de 16 KiB. **La biblioteca `libspdecode_result_engine.so` de resultados grandes se valida únicamente en el plan de resultados descifrados**, no es prerrequisito del directorio.
- Iconos no modificados se reutilizan; crecimiento del catálogo no dispara necesariamente el mismo volumen de red.
- Interfaz muestra la edición editorial verdadera, p. ej. v13 **si fue confirmada**, y watch/sync mantiene su entero técnico alto.
- El panel/admin y el VPS no anuncian versiones que carecen de objetos publicados, no hay pérdida de switches ni claves.
- APK anterior sigue actualizando el catálogo según su contrato mientras esté soportada; migración y rollback probados.
- Se prueba en dispositivo físico, se reporta evidencia y se revisa CI antes de merge a `main`.

## 12. Documentos relacionados y notas de alcance

- `docs/android/EXTERNAL_IMPORT_CATALOG_MODAL_2026_11_04.md`: modal actual y corrección de importaciones externas (seguir preservando).
- `docs/cloud/C10_CATALOG_DELIVERY.md`: contrato actual de watch y cache por versión; distinguirlo de futuros chunks.
- `docs/cloud/CATALOGS_UPDATE_RUNBOOK.md`: procedimiento de actualización Cloud, volúmenes y versión efectiva.
- `cloud/web/lib/c12-provider-controls.mjs`: revisión interna del catálogo y persistencia de switches.
- `cloud/web/lib/catalog-envelope.mjs`, `v2-transport.mjs` y `android/app/src/main/cpp/spdecode_hpke.cpp`: contratos criptográficos actuales, no modificar sin pruebas de compatibilidad.
- `android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/CatalogEnvelope.kt`, `ServerVpnSecureCache.kt`, `ServerVpnCatalogRepository.kt`, `CatalogTransferDialog.kt`: puntos de migración.
- `analysis/METHOD_EVIDENCE_POLICY.md`: política de evidencia de métodos; los cambios de catálogo no confirman automáticamente que un descifrador funcione.
- `docs/FASE_7_CUENTAS_GOOGLE_PAGOS_Y_SOPORTE_APK_2026_11_04.md`: módulo comercial independiente; **no fusionar** la arquitectura de descarga de catálogos con uploads de APK de pago sin diseño explícito.

**Fuera de alcance en este commit:** modificar servidor/VPS, configurar proxy, crear/borrar ramas, implementar `.so`, modificar Gradle/Kotlin/C++, subir la versión Android, compilar APK/AAB, tocar cuenta Google Play o fusionar a `main`. El motor de resultados extensos y el visor Compose se documentan en `docs/android/RESULTADOS_DESCIFRADOS_JSON_GRANDES_MOTOR_NATIVO_2026_11_04.md`. Es planificación y especificación solamente.
