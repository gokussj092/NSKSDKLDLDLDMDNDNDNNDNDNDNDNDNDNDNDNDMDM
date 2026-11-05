# SP-DECODE — Resultados de descifrado extensos: motor JSON nativo y visualización sin crashes

**Fecha:** 2026-11-04. **Rama:** `feat/nuevas-integraciones`.
**Estado:** ESPECIFICACIÓN / PENDIENTE DE IMPLEMENTACIÓN. Solo documentación. No modificar todavía APK, servidor, compilar ni desplegar.

## 0. Aclaración del propietario — problema y alcance exactos

**CORRECCIÓN CRÍTICA:** el crash reportado por el propietario NO ocurre al descargar ni cargar el **catálogo de aplicaciones Server VPN**. Ocurre cuando SP-DECODE **descifra archivos o catálogos de configuraciones VPN** y trata de **procesar, presentar o volver a abrir resultados JSON muy extensos** (ejemplo: más de **8,000 líneas**). La palabra «catálogo» en este contexto se refiere al **resultado de una decodificación de configuraciones VPN** con numerosas entradas, NO al catálogo de metadatos `ServerVpnCatalogRepository`.

- Problema A, documento independiente: descarga/progreso/reanudación del inventario Server VPN → `docs/cloud/CATALOG_SERVER_VPN_RESUMABLE_NATIVE_ENGINE_PLAN_2026_11_04.md`.
- Problema B, **este documento**: recepción, persistencia, análisis, árbol JSON, scroll, redacción, copia y exportación de **resultados descifrados grandes**.
- **No hay evidencia aún** que pruebe qué fase exacta hace crashear la aplicación: parseo, memoria Java, memoria nativa, Compose, historial, OOM, stack overflow o excepción no manejada. El número de líneas por sí solo no demuestra el origen. El código revela riesgos de alta cardinalidad que deben medirse y corregirse.
- El objetivo es soportar **8,000 líneas o muchas más**, siempre dentro de límites de recursos explícitos y con manejo seguro de errores, **sin truncar el resultado**, alterar valores, eliminar servidores VPN, recortar nodos ni cambiar el contenido exportado.
- La propuesta de biblioteca nativa exclusiva para **resultados**, con nombre provisional `libspdecode_result_engine.so`, es independiente de cualquier futura biblioteca opcional para ingestión de metadatos del catálogo Server VPN. **No confundir ambas bibliotecas**.
- Mantener todas las medidas de protección Cloud: backend descifra, APK Cloud no incorpora métodos del servidor; el motor de resultados solo **parsea, indexa, conserva y sirve vistas limitadas de resultados ya autorizados**. Ninguna clave ni ruta del servidor se introduce en Kotlin o JNI.
- Los resultados puedan ser JSON estructurado, texto tipo bot con campos y JSON embebido, o un catálogo de servidores muy amplio. No asumir que 8,000 líneas necesariamente es un objeto JSON plano.

## 1. Evidencia de código: puntos concretos bajo auditoría

Archivos verificados en `feat/nuevas-integraciones`:

### 1.1. Ruta desde Cloud al resultado

- `android/app/src/main/java/com/ghostdeveloper/spdecode/cloud/CloudDecodeClient.kt`: `decodedResponse()` extrae `rawText` de la respuesta completa (`JSONObject`), lo convierte a `String`; aplica cota actual **4 MiB en resultados ordinarios y 32 MiB para MKK** (distinta del límite de entrada `MAX_INPUT=8 MiB`). El tamaño de texto en líneas no equivale al tamaño en bytes.
- `android/app/src/main/java/com/ghostdeveloper/spdecode/MainActivity.kt`: se construyen y guardan `DecodeView` y se carga en sesión/Historial el `rawText`. Verificar en QA si se generan copias adicionales durante la transición a la pantalla y guardado cifrado.
- `android/app/src/main/java/com/ghostdeveloper/spdecode/SecureDecodeHistory.kt`: se serializa `rawText` como JSON de registro, se cifra y persiste; revisar límites, número de copias, lectura total y tiempos. El trabajo de almacenamiento debe estar fuera de UI.
- `android/app/src/main/java/com/ghostdeveloper/spdecode/CompleteResultCard.kt`: muestra el contenido mediante `JsonTreeViewer(raw=current.rawText,...)`. Copy y Export deben mantener el resultado íntegro.

### 1.2. Riesgo del visor actual (hipótesis técnicamente fundada)

- `ResultJsonDisplay.kt`: usa Gson `JsonParser.parseString`, `ResultPresentation.parse`, `normalize` recursivo y copias `deepCopy` para construir otro árbol. `render()` hace `prettyPrint`; el coste puede ser varias veces el tamaño de `rawText`.
- `JsonTreeViewer.kt`: el parseo usa `Dispatchers.Default`, lo cual evita bloqueo directo de parseo en Main, PERO el resultado termina en un `JsonElement` completo, después crea `rows` y renderiza con `Column { rows.forEach { ... Text / SelectionContainer ... } }`.
- `JsonTreeProjection.kt`: todas las ramas están abiertas por defecto, `project()` produce una `List<Row>` para cada rama visible expandida, y `rows.forEach` incorpora cada fila en Compose sin virtualización. Un JSON de miles o decenas de miles de nodos puede provocar sobrecarga de composición, diseño, accesibilidad y estado, además del uso de memoria.
- `ResultPresentation.kt`: conversión de texto mixto a JSON y representaciones adicionales; `MAX_FIELDS=1500` limita un listado interno, **no** debe interpretarse como permiso para recortar el contenido que se muestra/exporta. Auditar transformaciones para asegurar fidelidad.
- `RawResultFormatter.kt`: contiene topes de procesamiento visual, pero el visor principal usa `ResultJsonDisplay`; no dar por solucionado un crash del árbol simplemente porque otro formatter tiene límites.

**El modo exacto de fallo solo puede concluirse con logcat/stacktrace y medidas de memoria.** Evitar afirmar que `JsonTreeViewer` es la única causa o que «más de 8,000 líneas» supera un límite fijo.

## 2. Definición funcional: archivos grandes sin perder resultados

1. Nunca eliminar servidores, usuarios, nodos, atributos, JSON anidado, extensiones ni líneas por motivos de interfaz. El resultado original debe permanecer accesible para copiar/exportar/historial, dentro de un límite de servicio explícito.
2. Vista inicial fluida y ligera, incluso si el resultado tiene muchos miles de entradas. El usuario **no necesita que Compose cree todos los elementos simultáneamente** para poder consultar el resultado completo.
3. Navegar/expandir/plegar JSON bajo demanda; búsquedas incrementales opcionales; visualización paginada/virtualizada preservando orden y rutas/índices.
4. Mantener el estilo AMOLED aprobado y el resaltado de sintaxis de JSON, pero **solo** para las filas visibles y con presupuesto de trabajo por frame.
5. Protección de credenciales en pantalla, incluso al cambiar el toggle revelar/ocultar durante carga, rotación o reciclaje de filas. El texto sin enmascarar nunca debe reaparecer por un error de caché.
6. Copy/Export deben generar el documento **íntegro**, con la redacción exacta según la opción elegida, sin crear una sola `AnnotatedString` de megabytes ni enviar contenidos sensibles a logs, crash reporters o almacenamiento externo no solicitado.
7. Nunca tratar una respuesta «parcial» como «completa». Distinguir catálogo de servidores decodificado de metadatos de directorio de apps; no cambiar los contratos originales de descifrado.
8. Si hay memoria/disco insuficiente, mostrar error controlado o «No se puede abrir la vista previa completa en este dispositivo; exportación disponible» **solo** si el resultado íntegro está ya guardado de forma verificable, sin perderlo ni prometerlo falsamente.

## 3. Arquitectura propuesta: resultado íntegro + índice + viewport

### 3.1. Unidad de trabajo: `DecodedResultSnapshot`

- Identificador estable de trabajo/historial; formato; longitud en bytes; checksum SHA-256 del documento original; fecha; tipo de contenido detectado; versión del esquema de índices.
- El original se conserva de forma **cifrada y autenticada**, con commit atómico. No depender de un `String` gigante dentro del ViewModel durante toda la sesión.
- Indexar campos, arrays, rangos de byte y rutas de nodos. Validar los offsets al reabrir; ningún índice será autoridad sobre la autenticidad del resultado.
- Un índice es **derivado** y regenerable si cambia el motor; la fuente de verdad es el resultado original verificado.
- El formato de origen puede ser JSON ya parseable o texto plano; se debe proporcionar una representación JSON de visualización sin modificar el original. Diferenciar `rawOriginal` de `displayProjection`.

### 3.2. Motor nativo `libspdecode_result_engine.so` (nombre de diseño)

Funciones propuestas, **no implementadas**:
- `openResult(handle/pathAuthorized, format)`: abrir registro autorizado a través del almacén seguro y validar límites/checksum.
- `indexDocument`: parseo streaming SAX/iterativo con límites de anidamiento, tokens, bytes, tamaño de clave/valor y UTF-8. Para texto tipo bot, lexer/transformación incremental sin producir otra cadena completa.
- `getRootSummary`, `listChildren(nodeId, offset, limit)`, `getValueSlice(nodeId, offset, limit)`, `searchNodes(query, cursor)`: API de navegación **bounded** y paginada; cada respuesta JNI contiene solo datos pequeños.
- `renderJsonRange` opcional: generar parte de la representación visual con tokens sintácticos o offsets, sin `pretty print` total ni DOM gigante.
- `exportResultToStream`: copia exacta del documento original, o exportación JSON total por streaming, a un `OutputStream` elegido explícitamente por el usuario, sin truncamientos y con verificación de bytes/hashes.
- `closeResult`, `cancel`, cierre RAII y liberación de índices incluso cuando la Activity termina.

**Selección del parser:** evaluar RapidJSON SAX u otra librería C++ con licencia y checksums aprobados, robusta ante JSON malformado y fuzzable. En texto tipo bot, definir formalmente escapes, arrays, campos duplicados, saltos de línea y formatos mixtos para no perder información.

**Separación de responsabilidades:** CloudDecodeClient sigue gestionando comunicación/atestación/HPKE. ResultEngine procesa **solo resultado ya descifrado**, sin implementar descifradores de apps ni claves de terceros. Keystore gestiona llaves no exportables vía puente Android controlado; JNI no debe recibir claves exportadas.

### 3.3. UI Compose virtualizada (requisito independientemente del motor `.so`)

**El motor C++ por sí solo NO arregla un `Column(rows.forEach)` de miles de elementos.** Debe sustituirse la estructura visual por `LazyColumn`/`LazyList` con carga bajo demanda desde el motor y representación de filas visibles. Mantener scroll estable y claves estables; evitar calcular todo `List<Row>` antes de dibujar.

- Inicialmente mostrar nodos de nivel superior y arrays plegados; «Expandir» solicita páginas según demanda.
- Paginación por nodo, sin expandir 8,000 hijos automáticamente; controles «Ver siguientes N», búsqueda o vista fragmentada para listas grandes, sin perder acceso al resto.
- `AnnotatedString`/colores se calculan **por fila visible**; no resaltar el documento entero ni construir múltiples buffers de pantalla.
- Expansiones se mantienen en estructura compacta; cambiar mascarado invalida de inmediato todas las vistas cacheadas (con rol/estado) para evitar mostrar secretos antiguos.
- Selección/copia de entradas individuales es opcional; «Copiar todo» y «Exportar» funcionan por streaming o mecanismos acotados.
- La capa de accesibilidad debe tener cientos de nodos **visibles**, no miles de nodos simultáneamente.

### 3.4. Límite de memoria y formato de índices

- Cotas de entrada, profundidad, longitud de cadena, número de índices y tamaño de respuesta JNI; evitar desbordamiento entero y descompresión peligrosa.
- Fijar presupuestos medidos con dispositivos reales; los tamaños máximos de respuesta Cloud y de registro en historial se coordinan con backend y motor.
- Índices persistentes compactos cifrados o memoria acotada; no crear duplicados de `rawText` + JSON bonito + Gson tree + tree normalizado + todas las filas + selección de texto.
- El renderer de «vista previa» puede mostrar páginas pequeñas; **no** debe limitar la exportación completa.
- Manejar `OutOfMemoryError`, `StackOverflowError`, excepciones Kotlin y errores nativos con medidas preventivas; no confiar en que atraparlos después de agotar heap rescatará el proceso.
- Probar bibliotecas ABI/16 KiB, símbolos JNI, estados de proceso y políticas de backup. Que una `.so` sea exclusiva no implica seguridad ni rendimiento automáticamente.

## 4. Transporte, formatos y almacenamiento: no confundir límites

- `CloudDecodeClient.MAX_INPUT=8 MiB`: máximo de **entrada** de configuración VPN, no «8,000 líneas».
- `CloudDecodeClient.decodedResponse()`: resultado ordinario de hasta **4 MiB** y excepción MKK de hasta **32 MiB**. Son límites actuales del resultado **en bytes**, no capacidad garantizada del visor. No ampliarlos antes de tener rendering y almacenaje escalables.
- `spdecode_transport.cpp` y `v2-hpke.mjs`: reciben/encriptan respuestas Cloud actuales. Si realmente se necesitan resultados enormes, planificar un protocolo de descarga de resultados separado y autenticado, posiblemente por fragmentos, evitando copiar un sobre completo en todas las capas. **No está autorizado ni diseñado en detalle aquí**.
- `SecureDecodeHistory.kt`: validar tamaño máximo del registro, memoria y escritura; migrar sin pérdida histórica y sin cambiar semántica de cifrado o favoritos.
- Exportaciones **ORIGINAL/JSON/ORDERED** y compatibles/unlocked deben pasar pruebas de fidelidad, sin alterar autorización Cloud ni contenido binario. `unlocked` no es necesariamente JSON y no debe pasar por el parser de resultados JSON.
- El problema de descarga del **catálogo de directorio Server VPN** sigue su propio plan resumible y no comparte por defecto los formatos/índices de resultados decodificados.

## 5. Diagnóstico obligatorio antes de elegir fix

Capturar con una muestra legítima/autorizada mayor de 8,000 líneas (datos anonimizados/sintéticos equivalentes para CI) y logcat sin payloads ni credenciales.

Hitos y trazas a distinguir:

1. Resultado generado en Cloud; `rawText` y bytes efectivamente recibidos, código HTTP y validación de `status`/`isPartial`.
2. Descifrado y verificación HPKE de respuesta; memoria antes/después, sin loguear texto claro.
3. `decodedResponse()`: extracción de `rawText` y validación de límite.
4. Construcción `DecodeView` y guardado cifrado en historial; tamaño/tiempo.
5. `ResultJsonDisplay.element()` y `ResultPresentation.parse()`: tiempo, tokens, asignaciones Java/Native.
6. `JsonTreeProjection.project()`: número de filas generadas, profundidad, tamaño e invocaciones repetidas.
7. `JsonTreeViewer` Composable: memoria, número de nodos UI, frame time, ANR vs OOM, rotación y navegación.
8. `Copy` y `Export`: tamaño, flujo y resultado; efecto de compartir con proveedores.
9. Reabrir desde Historial, modo ocultar/revelar credenciales, almacenamiento insuficiente.
10. Clasificar `OutOfMemoryError`, excepciones no manejadas, `SIGSEGV`, `SIGABRT`, `StackOverflowError` y ANR con stack concreto. Evitar enviar resultados descifrados a servicios externos de crash reporting.

**No atribuir el crash a 8,000 líneas por sí solo.** Medir bytes UTF-8, número de nodos, longitud máxima de un valor, profundidad, memoria inicial, procesos y stack.

## 6. Plan de implementación por fases

| Etapa | Entrega y criterio de salida |
|---|---|
| **R-0** | Reproducción del crash con muestra larga y logcat sin contenido; identificar capa exacta. |
| **R-1** | Hotfix seguro de UI: eliminar expansión masiva/render eager, virtualizar filas, evitar parse repetido; preservar contenido. No requiere `.so` inicialmente si corrige la causa real. |
| **R-2** | Contrato de `DecodedResultSnapshot`, índices, cache cifrado y métodos de paginación; migración de historial y pruebas de integridad. |
| **R-3** | Crear `libspdecode_result_engine.so` exclusivo y JNI acotado; parser/lexer incremental, fuzzing y límites. |
| **R-4** | Integrar lazy tree, resaltado por viewport, búsqueda opcional y gestión de credenciales. |
| **R-5** | Copiar/exportar original completo mediante streaming y reabrir historial grande; validar opciones JSON/ORIGINAL/ORDERED/unlocked con contratos separados. |
| **R-6** | Test Android real, QA de rendimiento, crash handling, 14 idiomas, release gating; desplegar solo con pruebas aprobadas. |

**Dependencias:** R-0 determina el hotfix mínimo; R-1 puede ser urgente e independiente de la biblioteca nativa. R-2/R-3/R-4/R-5 se diseñan juntos para no duplicar conversión de resultados. Si el problema real está en el backend o HPKE, repararlo en la capa correspondiente antes de aumentar cotas.

## 7. Pruebas obligatorias

- JSON sintético de **8,000**, **20,000**, **50,000** líneas, y arrays con miles de objetos, así como archivos VPN reales autorizados (sin secretos en repositorios).
- Mismo contenido representado compacto en una línea y pretty-printed en 8,000 líneas: confirma que bytes/nodos, no líneas, son la dimensión limitante.
- Valores enormemente largos en una sola línea; JSON con profundidad 1, 10, 50, 200 y anidamiento inválido; Unicode, emoji, CRLF, campos duplicados y JSON embebido como string.
- Configuración tipo bot con 8,000 líneas de servidores VPN, campos mixtos y JSON anidado.
- Rotación y background/foreground mientras se renderiza; bloqueo del teléfono y proceso muerto; apertura desde Historial.
- Reveal/mask 100 veces durante carga; jamás mostrar contraseña en frame incorrecto. Scroll a inicio/mitad/final; nodo profundo; paginación y scroll restore.
- Llamadas de Copy/Export y exportación compatible/unlocked sobre contenido largo; hash SHA-256 del original antes/después y bytes de salida sin truncar.
- Dispositivos con poca RAM, Android 13–16, 16 KiB, stress/GC, benchmark de cold/open/historial y frame time; ausencia de ANR/OOM/SIGSEGV.
- Corruptos, incompletos, nulos, múltiples bytes UTF-8, interrumpir persistencia y falta de disco: error manejado y sin perder resultado guardado.
- Test de regresión de resultados cortos existentes y de todos los formatos Cloud; APK sin métodos de descifrado local añadidos.

**Aprobación:** la app debe manejar la muestra real que antes la cerraba, mostrar todas las entradas mediante navegación sin bloquear la UI y permitir exportar/copiar el contenido íntegro. Guardar tiempos y memoria medidos; no inventar resultados de tests.

## 8. Diseño UX de resultado largo (maqueta textual)

    Resultado descifrado
    Archivo: catalogo_de_servidores.vpn
    Contenido disponible: 8,000+ líneas / N entradas

    ▸ Servidores (8,421 elementos)
    ▸ Configuración
    ▸ Metadatos

    [Buscar] [Expandir sección] [Copiar todo] [Exportar]

    (Las filas se generan al desplazarse. Abrir Servidores muestra
     un tramo y permite avanzar, sin cargar 8,421 elementos visuales.)

La cantidad se calculará de datos reales y nunca truncará el contenido. El estilo será AMOLED existente; la previsualización no implica creación de nueva pantalla, porque puede ser una mejora del visor actual.

## 9. Documentación relacionada

- Plan separado para descarga **del directorio** Server VPN (progreso/chunks/versiones visibles): `docs/cloud/CATALOG_SERVER_VPN_RESUMABLE_NATIVE_ENGINE_PLAN_2026_11_04.md`.
- `docs/android/EXTERNAL_IMPORT_CATALOG_MODAL_2026_11_04.md`: modal de descarga, NO visor de resultados.
- `docs/V2_HPKE_TRANSPORT.md`: transporte Cloud, firma y cuotas.
- `analysis/METHOD_EVIDENCE_POLICY.md`: scripts e integridad de métodos server-side, no metadatos de vista previa.
- `docs/FASE_7_APK_AUTOANALISIS_DOS_SALIDAS_PENDING_2026_11_02.md`: análisis de APK de pago, sistema completamente distinto.

**Alcance de este commit:** crear documentación para resultados extensos y aclarar el alcance del plan del directorio Server VPN. NO modificar Kotlin, C++, JNI, Cloud, credenciales, endpoints, Gradle, versionCode, APK, AAB ni main.
