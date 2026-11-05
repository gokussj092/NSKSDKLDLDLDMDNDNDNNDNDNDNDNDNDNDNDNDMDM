# Catálogo reanudable y resultados extensos: implementación del 2026-11-05

Rama: `feat/nuevas-integraciones`. Continuación autorizada por el propietario de los dos planes del 2026-11-04. El cambio incluye código de servidor y Android; no cambia versión/firma de APK ni publica una aplicación. La integración independiente de XXPICore está en `1b55fa6d39b92c21580527368dfebb0184bece0e` y su expediente `analysis/pro.xxpicore.tunnel/118/`.

## Estado comprobado

| Área | Implementación | Validación y gate pendiente |
|---|---|---|
| Directorio Server VPN | Manifest inmutable, objetos por hash, chunks de 256 KiB, operaciones HPKE 19/20, retención, journal cifrado, reanudación, commit atómico y PNG diferidos | API y descarga real de código Kotlin con transporte/caché simulados; falta VPS, Android físico y 50/100 kbps reales |
| Edición visible | `displayVersion` explícita en C12/admin, con avance auditado y publicación antes de anunciarla | Pruebas de avance, rollback, switches y fallo de publicación; no se ha asignado una edición de producción ni supuesto que sea 13 |
| Resultados extensos | `libspdecode_result_engine.so`, índice iterativo, páginas y valores acotados, LazyColumn, ramas pequeñas plegadas | ASAN/UBSAN, JNI real en JVM host y Kotlin de producción; falta Android/ABIs/16 KiB y rendimiento físico |
| Historial | Registro AES-GCM v2, metadatos v4, SHA-256 del original, AtomicFile; lista sin cuerpos; apertura individual en IO | Codec real probado en JVM; pruebas Android Keystore/AtomicFile añadidas pero no ejecutadas |
| Copia/exportación | Original exacto y JSON/ordenado mediante Writer; elimina el límite de 1.500 campos de la ruta grande | Casos de 8.000/20.000/50.000 entradas y 8.000 líneas mixtas; falta proveedor SAF/portapapeles físico |

**No se reprodujo el cierre original:** no se dispone de logcat ni muestra del dispositivo afectado. R-0/D0 siguen abiertos. No se afirma que la causa fuese OOM, Compose o un número concreto de líneas. Las pruebas host no sustituyen compilación/tipos de Compose, carga de la biblioteca Android, medidas de memoria/frame time o QA físico.

## Protocolo del directorio

- El servidor conserva `catalogVersion` técnico monótono. `displayVersion` es opcional, editorial y no se deriva de ese entero. El mínimo de código permanece en 73; se respetan overrides/revisiones persistentes mayores.
- Flag `CLOUD_CATALOG_CHUNKS_ENABLED`, **false por defecto**. Cuando está apagado, watch no anuncia `catalog-chunks-v1`; clientes nuevos conservan el endpoint legacy. No se degrada a legacy tras un error criptográfico o de integridad.
- Con el flag encendido, watch prepara el snapshot antes de anunciarlo. Manifest/chunk solo admiten contexto HPKE vinculado por el servidor, con la autenticación, PoP, replay protection, atestación, hardware y RASP existentes. Las rutas V1 de adaptación no aceptan por sí solas una cabecera de cliente que alegue HPKE.
- `snapshotId = manifestHash = SHA256(bytes exactos del manifest)`. El manifest incluye protocolo/esquema, revisiones, creación/caducidad, suma lógica y cada objeto con longitud, tamaño/cantidad de chunks y hashes. No contiene URLs de proveedores, métodos, claves o perfiles VPN.
- Objetos: un JSON de metadatos de hasta 2 MiB y PNG originales individuales; máximo 500 apps/501 objetos, 6 MiB por objeto, 64 MiB lógicos. Los objetos se deduplican por SHA-256. El constructor comprueba nombres/IDs y cabecera PNG; Android además valida dimensiones/formato/hash antes de activar el catálogo.
- Publicación: objetos → manifest → índice. Escrituras de archivo con fsync y rename. Retención 7 días y cuota conservadora de 256 MiB; se eliminan snapshots caducados/objetos sin referencias durante publicación, sin expulsar uno válido para hacer sitio. Caché de preparación de 5 minutos/8 variantes evita releer PNG en cada watch.
- Lease Redis de 30 minutos vinculado a sesión y snapshot; se renueva sobre el mismo snapshot tras expirar. Límite 120 solicitudes/minuto/sesión. 429 devuelve `Retry-After: 60` y `retryAfterMillis` dentro del contenido autenticado; cliente aplica hasta 2 reintentos transitorios con espera y jitter. Auth/hash/schema no se reintentan como si fueran una caída de red.
- Rutas fijas, sin URLs de descarga arbitrarias. Conexión 10 s e inactividad de lectura 60 s para catálogo; sin plazo total de transferencia. Cancelar desconecta los HTTP activos y conserva lo ya verificado.
- El estado editorial se publica mediante el formulario admin existente con autenticación y CSRF. Se valida avance y se guarda auditoría de las últimas 10 ediciones; con chunks habilitados, un fallo de preparación no cambia la edición persistente.

## Bytes, caché e interfaz

El total de la ruta nueva significa **payload de los objetos que no están completos en la caché verificada**; excluye objetos completos reutilizados, sobre HPKE/Base64 y cabeceras HTTP. Los chunks parciales recuperados se vuelven a verificar y cuentan al recorrer el objeto. Puede haber un salto de progreso al recuperar bytes locales, sin repetirlos en red. La suma lógica de todo el snapshot queda en el manifest, separada del denominador pendiente.

La ruta legacy sigue midiendo bytes HTTP; ahora el servidor declara Content-Length del ciphertext sellado. No se comparan los dos tipos de contadores como si fueran iguales.

La UI expresa MiB (1.048.576 bytes), muestra total cuando se autentica el manifest y solo usa indicador desconocido antes de conocerlo. «Verificando y guardando» distingue todos los bytes recibidos del catálogo ya activado; no se muestra éxito ni botón Finalizar antes del commit. Pausa/reintento, borrar parcial y aviso de conservación se incluyen en los 14 idiomas existentes. El número técnico se oculta cuando falta una edición editorial.

El journal y los objetos/partes utilizan la caché no-backup con Android Keystore AES-GCM. Se verifican cada chunk y objeto antes del commit del catálogo. El catálogo anterior y sus iconos sobreviven a fallos/cancelación. La limpieza derivada tiene TTL de 7 días y cota 96 MiB, y nunca elimina el catálogo/iconos activos. Revocar consentimiento cancela y solicita borrar staging bajo el mutex del repositorio. Se conservan los switches, las claves y los volúmenes existentes.

## Motor de resultados y fidelidad

Parser propio C++17, sin dependencia de parser JSON de terceros. Usa pila iterativa y nodos planos con rangos de bytes, conserva claves duplicadas, orden y bytes originales. Cotas: 32 MiB UTF-8/documento, 200.000 nodos, profundidad 200, clave de hasta 4.096 bytes. Registro JNI de como máximo 2 documentos y 32 MiB de fuente combinada. Entradas inválidas/fuera de presupuesto generan error controlado, no un resultado recortado.

La API Kotlin `NativeResultEngine.Document` ofrece `page`, `value`, `exportOriginal`, `close`; páginas de hasta 64 filas y respuesta JNI hasta 64 KiB, valor inicial 256 bytes, detalle hasta 4.096 bytes por solicitud y exportación en bloques de 65.536 bytes. En casos con muchos escapes caben menos filas; el cursor siguiente preserva el resto. Claves de pantalla se abrevian a 256 bytes; su texto completo permanece en el original exportable. Las páginas se virtualizan en un viewport acotado; cambiar privacidad destruye inmediatamente filas/diálogos anteriores. No se construye un DOM Gson completo para documentos grandes (64 Ki caracteres o más, o más de 1.000 separadores de línea).

Texto mixto se indexa por líneas físicas, con blancos/CRLF originales preservados. En privacidad, las líneas mixtas y strings opacos con escapes se ocultan de forma conservadora, ya que pueden contener credenciales o JSON embebido. Revelar permite consultar sus páginas; original/historial no se alteran. Búsqueda nativa incremental sigue siendo opcional y no está implementada.

Los documentos pequeños usan normalización iterativa limitada y ramas anidadas plegadas, con LazyColumn. El índice es derivado, en memoria y regenerable, no una autoridad sobre el contenido cifrado.

`ResultSnapshotCodec` evita citar todo el resultado dentro de otro JSON: escribe metadata y UTF-8 a través de AES-GCM con AAD ligado al UUID. En lectura usa `Cipher.update/doFinal` explícitos, verifica tag/EOF y checksum antes de interpretar/publicar el documento. No delega la autenticación a `CipherInputStream`, cuya documentación advierte limitaciones para AEAD: [referencia oficial JDK 17](https://docs.oracle.com/en/java/javase/17/docs/api/java.base/javax/crypto/CipherInputStream.html). La lista de historial carga metadatos autenticados sin conservar los cuerpos; el seleccionado se abre en IO. Se mantienen los lectores del registro v1/metadatos v1–v3, favoritos y el índice Room sin contenido privado.

**Límite de esta entrega:** el contrato Cloud/DecodeView aún entrega y conserva un String del resultado seleccionado, y JNI mantiene su fuente UTF-8 acotada. No es un sistema completamente basado en handles de disco sin materialización. El cifrador GCM del proveedor también puede emplear buffers internos. El rediseño elimina los cuerpos del listado y las copias DOM/pretty de la vista grande; el pico real de una sesión de 32 MiB necesita medición en Android de poca RAM. No se aumentan las cotas existentes de Cloud (4 MiB ordinario/32 MiB MKK).

Exportación grande ORIGINAL copia el texto UTF-8 completo; JSON estructurado se valida con parser incremental estricto (profundidad 200) y conserva su orden/duplicados/bytes. Texto mixto JSON se representa como `{format, raw}` para conservar incluso saltos CRLF y campos repetidos. ORDERED recorre todos los campos sin el tope de 1.500, conserva duplicados y añade el encabezado existente; texto tipo bot conserva el original ordenado. La exportación de archivos no lleva el wrapper Markdown del portapapeles. Compatible/unlocked conserva su ruta binaria separada.

El portapapeles de Android tiene un límite de Binder variable: se rechazan preventivamente cuerpos de más de 200.000 caracteres o una salida de más de 250.000 caracteres para evitar materializar transacciones de varios MiB; los menores se preparan completos fuera de Main. Nunca se copia una fracción anunciándola como completa. Si rechaza el resultado se indica exportar el archivo íntegro. Una exportación escrita parcialmente por falta de espacio/proveedor SAF termina con error; solo se anuncia guardada después de finalizar el Writer.

## Reproducir pruebas sin crear APK

Desde un checkout completo con las dependencias Node fijadas del proyecto (`npm ci` en `cloud/web`):

```sh
python scripts/qa/catalog_results_host.py \
  --cache /tmp/spdecode-kotlin-parser \
  --jni-include /ruta/al/jdk17/include \
  --report /tmp/catalog-results-host-qa.json
python -m unittest discover -s analysis/pro.xxpicore.tunnel/118/tests -v
```

El runner Linux usa Java 17, g++ y Node. Descarga solo jars de Maven Central con versiones y SHA-256 fijados en `scripts/qa/catalog-results-dependencies.json`; no ejecuta Gradle, Android SDK, emulador, workflow, build APK/AAB o despliegue. JNI usa cabeceras del JDK, no cabeceras vendorizadas. Los tests host de descarga sustituyen HTTP/Keystore por fixtures explícitos; no certifican esos servicios Android. La fixture del publisher tiene bytes sintéticos con firma PNG y no certifica decodificación de imágenes.

Evidencia: `analysis/platform/catalog-results/2026-11-05/host-qa.json`. Resultado: **250 tests Node, ASAN/UBSAN con 5.000 entradas aleatorias, JNI en JVM host, compilación/ejecución de algoritmos Kotlin de producción y XML de 14 idiomas aprobados**; XXPICore: 11 pruebas Python aprobadas. LeakSanitizer se desactivó porque el entorno usa ptrace; no hay una prueba de fugas aprobada. PSI prueba sintaxis Kotlin, no resolución de tipos de toda la app Android. Un chequeo de sintaxis C++ del transporte tampoco equivale a enlazar la biblioteca Android.

## Activación y reversión pendientes

1. Revisar este PR borrador y el expediente del método. Ejecutar R-0/D0 con logcat sanitizado, misma muestra legítima y fases/memoria/HTTP medidos. No enviar resultados privados a crash reporting.
2. Servidor en staging primero: respaldar C12/secretos/volúmenes, crear volumen `catalog-snapshots` escribible, revisar cuota y timeouts Nginx. El compose declara el volumen pero no se aplicó en un VPS.
3. Habilitar `CLOUD_CATALOG_CHUNKS_ENABLED=true` solo en staging; probar sesiones/HPKE reales, publicación editorial, catálogo anterior, legacy y reanudación a 50/100 kbps con caída, sesión expirada y actualización de snapshot. Confirmar bytes de red no repetidos.
4. Cuando se autorice compilar, validar Android/ABIs/16 KiB y ejecutar tests instrumentados añadidos/actualizados, rotación, muerte de proceso, Keystore invalidado, SAF, TalkBack/RTL/14 idiomas, RAM/GC/frame time, 50/100/250/500 apps e iconos inválidos. La versión/firma de publicación requiere su gate independiente.
5. Despliegue gradual solo después de aprobar esos gates. Flag false revoca la capability para futuras negociaciones, conservando legacy y caché activa; una transferencia nueva pausa ante rechazo sin eludir integridad. No borrar snapshots aún válidos ni claves persistentes.
6. Una APK antigua no entiende registros de historial v2 recién creados, aunque los conserva en disco y sigue leyendo los v1. Antes de un downgrade de APK se debe validar una migración/lector compatible; no prometer reapertura de esos registros con código anterior.

El commit Android usa `[skip ci]` para evitar que el workflow automático de esta rama genere APK/AAB; no se declara CI completo aprobado.

No se modificaron los flujos de pagos, importación comercial de APK, Play publishing o generación automática de métodos de fase 7. No hay merge a main ni despliegue de producción en esta entrega.
