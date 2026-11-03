# SP-DECODE — Fase 7 (extensión futura): analizador automático de APK con DOS SALIDAS

**Fecha:** 2026-11-02. **Estado:** PENDIENTE / diseño integral; NO código de producto, no endpoints, no worker, no IA ni cobros habilitados.  
**Prioridad previa:** registrar y normalizar los scripts de investigación conforme a analysis/METHOD_EVIDENCE_POLICY.md.  
**Base vigente:** docs/FASE_7_ARQUITECTURA_SUSCRIPCIONES_CREDITOS_APK_2026_11_02.md. Mantener su contrato de suscripción, créditos y contabilidad, sin inventar precios para un segundo modo.  
**Visión del propietario:** que el usuario importe legalmente una APK en SP-DECODE, el servidor extraiga los datos técnicos y ofrezca dos resultados: **(A) informe y datos útiles** o **(B) código fuente generado mediante una API de IA (OpenAI o DeepSeek), con tests, más el informe**. El objetivo de largo plazo es reducir la búsqueda manual que antes realizaba el desarrollador.

## 1. Contrato de las DOS salidas

### MODO A — Datos e informe técnico (análisis sin generación de código)
Entrada: APK/APKS autorizada aportada por el usuario, categoría preferida (archivos, catálogos, texto, exportación) y consentimiento explícito.

Salida estructurada:
- Nombre de app, packageName, versionName/versionCode, SDK, ABI, icono/recursos públicos cuando sean reutilizables, SHA-256 de APK y de los módulos verificados, fecha y alcance de análisis.
- Inventario de manifiesto, componentes, permissions, DEX, librerías ELF, clases/recursos y ubicaciones de posible parser/serializador/criptografía.
- Formatos: extensiones, marcadores (magic bytes), posibles capas Base64/compression/JSON, algoritmos y longitudes observadas, sin afirmar claves o técnicas no verificadas.
- Catálogos: fuentes públicas autorizadas y endpoints declarados, evidencia estática de rutas, esquema tentativo y campos, claramente diferenciados de una descarga remota REAL validada. No enviar solicitudes de prueba a endpoints autenticados sin autorización.
- Qué información falta para terminar: contraseña que aporta el propio usuario, ejemplo de archivo autorizado, versión exportadora, API pública documentada, muestras de prueba con valores ficticios.
- Referencias a herramientas probadas de analysis/, expresiones de evidencia y comandos reproducibles. Los hallazgos se categorizan OBSERVED, INFERRED, UNVERIFIED, VERIFIED_REAL o VERIFIED_SYNTHETIC.
- Resultados JSON versionados (machine-readable) y resumen legible; entrega exportable sin incluir credenciales, JSON descifrado de terceros ni contenido secreto.

**Criterio de éxito A:** el informe debe contener datos técnicos reales observados en los bytes aportados, hashes, procedencia, límites y al menos el inventario básico verificable. Cuando algo no se pudo determinar, devolver UNKNOWN o NEEDS_INPUT, no rellenarlo con un ejemplo sintético no marcado.

### MODO B — Código asistido por IA (informe + proyecto de código y pruebas)
Se ejecuta MODO A primero. Si el usuario eligió B y la función está habilitada:
1. Recuperar herramientas verificadas y su documentación del índice de analysis/; seleccionar la familia y sus versiones de manera explicable (similitud no equivale a compatibilidad).
2. Sanitizar el informe. Construir un contexto limitado: metadatos, hallazgos, estructuras, código de herramientas con licencia/permiso apropiados y tests sintéticos/propios. No mandar APK completa, claves de usuario, firmas privadas, tokens o datos confidenciales a servicios de IA.
3. Por interfaz proveedor, pedir a un modelo permitido (OpenAI API o DeepSeek API) que **proponga** un módulo de parser/decodificador y sus pruebas, y que liste limitaciones y fuentes de evidencia. La IA no recibe capacidades de publicar, desplegar, escribir en main, gestionar VPS o usar secretos.
4. Validación automática del código: parse/lint, type checks según lenguaje, tests de fixtures autorizados, casos negativos, límites de tiempo/memoria, determinismo de salida, metadatos y contrato. Nunca ejecutar binarios ni código original extraído de APK de terceros. Ejecutar el código **generado** solo en sandbox desechable, sin root, sin red salvo allowlist explícita (preferentemente sin red), con filesystem read-only y permisos mínimos. El intérprete no debe poder acceder a llaves VPS ni a un contenedor Docker privilegiado.
5. Si fallan tests, permitir número acotado de iteraciones de reparación automática basadas en errores REDACTADOS; registrar cada intento y consumo sin prometer que siempre habrá éxito.
6. Entregar proyecto descargable con fuente legible, requirements/lockfile, README, comandos de reproducción, tests y reporte MODO A + matriz de resultados. No cargar automáticamente ese código al catálogo ni al worker de producción.

**Criterio de éxito B:** fuente propuesta compilable/parseable y tests automatizados en entorno aislado + evidencia trazable. Un test puramente sintético solo habilita el estado **GENERATED_TESTED_SYNTHETIC**, nunca **CONFIRMED_DECODER_FOR_APP**. Para declararlo apto debe existir prueba REAL autorizada por versión, salidas exactas contrastadas y revisión humana antes de integrar.

### Ejemplo de archivos entregables futuros

~~~text
report.json                    # informe estructurado, redacción de secretos
SUMMARY.md                     # resumen usuario, estado real del hallazgo
PROVENANCE.json                # fuentes permitidas, SHA-256 y scripts usados
CODE_GENERATED/                # solo modo B
  src/...
  tests/...
  requirements.txt
  README.md
  VALIDATION.json              # qué pasó, falló o no pudo probarse
  LIMITATIONS.md
~~~

Estado visible: COMPLETED_VERIFIED / COMPLETED_PARTIAL / NEEDS_INPUT / GENERATION_UNVERIFIED / FAILED / CANCELLED. Usar FAILED si la tarea no produjo material útil; nunca mostrar «descifrado» si solo se detectaron clases o algoritmos tentativos.

## 2. Flujo Android futuro (manteniendo UI aprobada actualmente)

ACTUAL: la pestaña APK de SP-DECODE 1.1.26 build 41 permanece deshabilitada, con «Próximamente», y Créditos no ofrece compras. No alterar esa pantalla ahora.
FUTURO, tras habilitar fase 7 y suscripciones:
- Pantalla «Analizar una APK» → selector SAF (no instalar ni ejecutar APK) → comprobación local de extensión/tamaño → aviso explícito de transferencia y procesamiento en Cloud.
- Selector exclusivo de resultado: **Informe técnico** o **Informe + código generado con IA**. Mostrar descripción del alcance y advertencia «el código puede requerir revisión manual».
- Confirmar precio/cargo antes de aceptar trabajo; no indicar tarifa inventada ni repetir textos comerciales que el propietario retiró de la maqueta de Créditos.
- Estado de trabajo por fases (validación, extracción estática, hallazgos, [modo B] generación, pruebas, empaquetado), sin simular progreso exacto si el servidor no lo puede medir. Consultar estado bajo sesión segura.
- Resultado con descargas de informe JSON y archivos de código según modo. Mostrar tests, confianza y límites.
- Historial privado de trabajos: cada resultado pertenece exclusivamente a su cuenta, con disponibilidad y caducidad explícitas.
- Localización en 14 idiomas, accesibilidad, ahorro de datos, aviso de archivos grandes, cancelación y reintento idempotente.

## 3. Arquitectura de servidor: módulos futuros y límites

~~~text
Android SAF + consentimiento
  -> Cloud API V2 autenticada (HPKE/PoP/Play Integrity según política)
  -> preflight / identidad + suscripción + reserva de crédito
  -> almacenamiento temporal CIFRADO (APK aislada por job)
  -> cola de trabajos con controles de CPU/RAM/tiempo/tamaño
  -> isolated-static-apk-analyzer
        -> validación ZIP/APKS + manifiesto + recursos/DEX/ELF
        -> hallazgos estructurados y estado de evidencia
        -> retrieval de analysis/ (índice aprobado, sin secretos)
        -> informe MODO A
        -> [solo MODO B] LLM provider adapter (OpenAI | DeepSeek)
            -> proposal -> linter -> sandbox tests -> repair bounded -> packaged result
  -> revisión de límites/estado final, contabilidad idempotente
  -> resultado cifrado descargable para propietario
~~~

Proponer servicios nuevos SEPARADOS del worker Cloud actual: AnalysisOrchestrator, StaticApkAnalyzer, EvidenceIndex, LlmCodeGenerationAdapter, SandboxTestRunner, ReportStore, BillingLedger, AdminReviewQueue. No incluir el motor de LLM dentro de JNI ni dentro de la APK cliente; claves/API keys SOLO servidor/secret manager.

### Entradas y contratos lógicos (NO implementar aún)
- preflight: identificador de formato y cuenta, SHA-256/tamaño, alcance autorizado y elección A/B. Rechazar ZIP bombs, traversal, enlaces simbólicos, APK excesivamente grande, múltiples archivos no permitidos y tipos no soportados.
- create job: idempotency key, mode, consentimiento y versión exacta de política comercial; reservar derechos únicamente después de confirmación.
- upload stream: bytes a objeto cifrado con TTL y quota, sin procesar antes de verificación completa; no poner bytes en Redis ni en logs.
- status: fases y reason codes, no secretos, ni rutas privadas, ni código completo en logs.
- results: autorización por cuenta, descarga temporal, checksum y versión de informe.
- cancel: cancelar workers y reconciliar reserva; limpiar artefactos según retención.
- audit: quién aprobó cambios de código, versión y resultado de tests, con identificadores pseudónimos.

**No reutilizar** las operaciones V2 existentes (ej. código de solicitudes/feedback) ni saltarse seguridad; los nuevos op codes y rutas necesitarán diseño/registro formal antes de producción.

## 4. Índice reutilizable basado en analysis/

- Fuente única: analysis/<paquete>/<build>/MANIFEST.json, ANALYSIS.md, REPRODUCE.md, RESULTS.md, tools/ y tests/.
- Ingerir solamente evidencias con estado y permisos compatibles; indexar rutas + hashes + versiones del método y herramientas; nunca cargar contraseñas o datos privados como contexto semántico.
- Motor de selección de herramientas: primero detectores robustos y genéricos, luego comparadores de familia/version_code; no suponer que un método de una app es válido para otra con el mismo nombre.
- Mapear herramientas compartidas en scripts/apk_analysis/ mediante manifest y wrappers; conservar el repositorio real como fuente de verdad.
- Versionar el índice y el analizador; resultado informa qué commit/análisis generó el diagnóstico. Cambios de método no deben invalidar resultados históricos sin una revisión.
- Antes de habilitar autoanálisis, completar la regla obligatoria documental y **activar CI que bloquea nuevos métodos sin expediente**. Sin ese gate, la automatización no tiene base confiable.
- Trabajos que incluyen información parcialmente no verificable producen informe parcial, no generación afirmada como válida.

## 5. IA: OpenAI API frente a DeepSeek API

**No existe una API «de ChatGPT» incorporada automáticamente por tener una conversación o una suscripción ChatGPT.** Para usar modelos de OpenAI desde tu servidor se requiere acceso y facturación separados a OpenAI API según la cuenta y tarifas vigentes. DeepSeek dispone de una API compatible con formatos de OpenAI, pero **NO debe asumirse gratuita ni ilimitada**. Su documentación pública actual indica facturación por tokens, con tarifas que cambian; verificar siempre antes de elegir.

Contrato LlmProvider independiente:
- complete_structured(prompt, sanitized_context, schema, token_budget, timeout) -> candidate.
- Implementaciones futuras OpenAIProvider y DeepSeekProvider; salida en JSON esquema cerrado, límites de costo por job y sesión; modelos configurables solo por admin.
- Claves almacenadas SOLO en backend (secret manager o env root-only) como futuros OPENAI_API_KEY o DEEPSEEK_API_KEY, nunca en repositorio, app, prompts, archivos descargables o logs.
- Controles: budgets por usuario/jornada, límite de tokens/reintentos/tiempo, sin acceso a red desde tests, circuit breaker, métricas de costo y fallback configurable. Si falta API válida, el MODO A sigue funcionando; el modo B devuelve PROVIDER_UNAVAILABLE de forma clara.
- No enviar documentación de terceros, bases de clientes ni código bajo licencia no reutilizable a LLM externo. Consentimiento informado sobre proveedores externos, retención y jurisdicción; posibilidad de elegir B solo si se acepta este procesamiento.
- Evaluar modelo local futuro si se requiere privacidad/costo predecible; no afirmar que un LLM reemplaza análisis, compilación ni QA.

Referencias de evaluación de costos vigentes (revisar antes de contratar):
- https://api-docs.deepseek.com/quick_start/pricing/
- https://platform.openai.com/docs/overview
- https://openai.com/api/pricing/

## 6. Pruebas de calidad, seguridad y revisión

MODO A:
- 10+ APK/APKS de clases diferentes y permisos de investigación claros; pruebas de ZIP, DEX múltiples, manifest binario, ARM64/armeabi, recursos faltantes, Unicode, archivo malformado, límites de tamaño/tiempo, idempotencia, caducidad.
- Hashes y metadatos correctos; falsas detecciones reportadas como posibles, no verdad.
- Sin ejecución de código de APK; análisis estático por defecto.

MODO B:
- Evaluación offline con métodos propios ya verificados, donde se conocen golden vectors; medir tasa de compilar, tests pasando, errores de método, falsos positivos, alucinaciones, costo medio y filtraciones de secretos.
- Pruebas adversarias de prompt injection escondida en cadenas de APK, manifest, recursos, comentarios y blobs: esos datos siempre son NO confiables y no instrucciones.
- El modelo no puede saltar la validación, autodeclarar VERIFIED ni habilitar un proveedor. Toda publicación de método generado requiere revisión humana por fase.
- Sandbox sin red, sin mounts de repo productivo/credenciales y con resource limits, seccomp y artefactos solo para lectura/escritura acotada.
- Comprobación de licencias si se empaqueta cualquier herramienta o contenido en el entregable.

Éxito real: prueba con muestras autorizadas, versión exacta, salida coincidente con referencia independiente, compatibilidad y negativos. No confundir tests de script sintético con conexión real al catálogo de otro servicio.

## 7. Crédito, suscripción, privacidad y entregables

- Respetar la base de fase 7: suscripción futura + créditos para análisis APK, con precio de referencia propuesto anteriormente, pero mantener toda UI actual en «Próximamente». El precio/cargo **del modo B con IA es una decisión comercial PENDIENTE**, ya que consume tokens y pruebas adicionales. No prometer mismo costo ni cobrar más sin aprobación expresa.
- Mantener ledger ACID e idempotencia de reservas. Fallos técnicos y proveedores IA indisponibles no deben cobrar un resultado prometido no entregado; reglas para informe parcial, cancelación y entrega fallida deben ser aprobadas antes de habilitar.
- Google Play Billing aplicaría a compras de funciones digitales distribuidas por Play, sujeto a requisitos/reglas aplicables; no activar checkout externo por esta documentación.
- Privacidad: consentimiento de subida, cifrado en tránsito y almacenamiento, retención limitada definida, borrado/descarga de resultados, RBAC. Registrar solo metadatos operativos seudónimos.
- No vender ni incorporar automáticamente a un catálogo compartido la información de APK del usuario; separar investigación propia verificada de trabajos privados de clientes.

## 8. Secuencia propuesta de implementación (ninguna etapa iniciada por este documento)

| Etapa | Trabajo | Puerta de salida |
| --- | --- | --- |
| A0 | Completar expedientes en analysis/ e implantar CI exigente de scripts | Nuevos métodos bloqueados si faltan evidencias |
| A1 | Parser ZIP/APKS estático, inventario de recursos/DEX/ELF y reporte JSON | Pruebas offline, hashes y límites validados |
| A2 | API V2 de trabajos + cola/worker aislado + almacenamiento efímero | Seguridad, cuotas, cancelación e idempotencia |
| A3 | MODO A: informe legible y descargable, validación de datos reales | Sin secretos ni afirmaciones no verificadas |
| A4 | LlmProvider: OpenAI/DeepSeek opcional + sanitización + control de costo | Tests adversarios, presupuestos y privacidad |
| A5 | MODO B: generar src/tests y ejecutar solo en sandbox | Calidad y estado UNVERIFIED vs VERIFIED |
| A6 | Review queue y exportación de proyecto final | Revisión técnica obligatoria para integraciones |
| A7 | Billing/identidad/suscripciones/aprobación comercial | Consentimiento, pagos reales y política de crédito |
| A8 | Beta cerrada y producción graduada | Auditoría de seguridad, tasas de éxito, costos y UX |

No empezar A1 hasta que A0 esté implementada y haya un corpus pequeño pero confiable. No fusionar, compilar APK de distribución ni desplegar worker/cobros sin aprobación.

## 8.1. Escalamiento a soporte humano — ruta de recuperación aprobada como requisito

**Decisión de producto:** cuando el servidor no logra obtener y verificar el resultado solicitado, crea un **caso de revisión humana**. El propietario de SP-DECODE y sus colaboradores autorizados podrán retomar el análisis manualmente, apoyarse en asistentes de IA durante una sesión iniciada por ellos, y entregar el resultado final desde un apartado privado del panel. No significa que ChatGPT vigile el panel ni resuelva tareas de manera autónoma en segundo plano.

**No es un tercer producto ni un tercer modo de compra**: el usuario sigue seleccionando MODO A (informe) o MODO B (informe + código); la revisión humana es una ruta de recuperación de cualquiera de los dos.

### Flujo de estados

~~~text
APK autorizada → análisis estático → [modo B] generación/test
        ├── entregable validado ------------------------------→ READY_FOR_DELIVERY → DELIVERED
        ├── información faltante -----------------------------→ NEEDS_USER_INPUT → reintentar / soporte
        ├── límite, fallo, incertidumbre o test fallido ------→ NEEDS_HUMAN_REVIEW
        │                                                       ↓
        │                                           HUMAN_CLAIMED → HUMAN_IN_PROGRESS
        │                                                       ↓
        │                                    HUMAN_NEEDS_USER_INPUT (si aplica)
        │                                                       ↓
        │                                  HUMAN_VALIDATION → READY_FOR_DELIVERY
        │                                                       ↓
        └───────────────────────────────────────── entrega privada desde panel → DELIVERED
                                    o FAILED_FINAL / CANCELLED (sin entrega válida)
~~~

- Escalar únicamente después de intentos automáticos acotados o ante incertidumbre; prohibir bucles de IA y reintentos facturables sin límite.
- Cada transición se registra con timestamps, motivo, actor y resumen saneado; un caso no cambia a DELIVERED solo porque se adjuntó un archivo.
- Si el usuario puede aportar voluntariamente una muestra propia o información adicional, utilizar NEEDS_USER_INPUT; nunca solicitar contraseñas de terceros o tokens privados para derrotar controles ajenos.
- En HUMAN_VALIDATION realizar pruebas reproducibles y contraste independiente cuando se afirme compatibilidad real. Si no es posible, ofrecer informe parcial claramente etiquetado y sujeto a aceptación, o cerrar como fallo técnico.
- La ruta manual conserva el **modo contratado**: A entrega informe; B entrega informe y fuente con tests si se pudo validar. No sustituir B por solo A sin aprobación explícita y ajuste de crédito según política aprobada.

### Panel administrativo — futura sección «Soporte APK»

Debe estar separada de notificaciones, catálogo y solicitudes/sugerencias. Para administradores autorizados:
- Bandeja de Pendientes / En revisión / Esperando datos / Listos para entrega / Entregados / No resueltos, filtros por fecha, paquete/versión, modo A/B y antigüedad.
- Detalle de caso: identificador opaco, hash del APK, cuenta autorizada pseudónima, modalidad, reporte inicial saneado, herramientas y scripts usados, hallazgos verificados/no verificados, fallos y pruebas pendientes.
- Tomar caso / asignar responsable / reasignar / notas internas / estado, con control de concurrencia para evitar duplicidad y auditoría.
- Acceso temporal al APK original **solo si el usuario consintió revisión humana** y el rol lo requiere; escaneo, almacenamiento temporal cifrado, aislamiento y TTL; nunca mostrar secretos ni archivos privados en logs o mensajes públicos.
- Carga desde panel de informe JSON, archivos de resultado y, para modo B, proyecto fuente + tests. Validar tamaño, formato, esquema, checksum, malware y ZIP seguro antes de publicar.
- Botón **Entregar resultado**: confirmar destinatario y ficheros exactos, estado de validación y revisor; operación autorizada, auditada e idempotente. Descarga con sesión de la cuenta dueña y enlaces temporales, no URL pública.
- Permitir devolver el caso al usuario para datos adicionales, rechazar análisis sin autorización o finalizar como no resuelto. El código generado nunca se publica automáticamente en el catálogo global.

### Vista de usuario, estado y notificaciones

- Ante fallo automático: mostrar **«Tu análisis requiere revisión manual»**, indicar el modo solicitado y que se intentará revisar; no asegurar fecha límite, éxito garantizado ni intervención inmediata.
- El historial privado de APK muestra estado y permite al usuario responder a solicitudes de datos, seguir esperando o cancelar conforme a la política comercial.
- Cuando esté READY_FOR_DELIVERY / DELIVERED, avisar por notificación opt-in o dentro de la app: «Tu análisis está disponible», **sin incluir nombre sensible, credenciales, hashes privados ni enlaces de descarga en el push**.
- Entregar solamente al propietario autenticado del trabajo. No exponer notas internas ni datos de otras cuentas; cualquier mensaje al usuario debe ser legible/localizado.

### Créditos, tiempos y finalización

- **Derivar a soporte no consume el crédito**: el caso sigue pendiente y la reserva se administra de modo idempotente. Definir tiempo máximo de reserva, liberación y cualquier re-reserva de forma transparente; evitar doble cobro o reserva permanente.
- **No cobrar por un análisis no resuelto**. Confirmar consumo solo al entregar el resultado útil acordado. Entregables parciales requieren aceptación expresa y tratamiento comercial aprobado.
- Cancelación durante revisión y sobrepasar el plazo máximo publicado deben permitir cierre sin cobro cuando no exista entrega válida.
- No habilitar una cola infinita sin límites de trabajos, ni prometer soporte humano 24/7. Medir volumen y tiempos durante beta y publicar plazos solo cuando sean operativamente sostenibles.

### Evidencia y privacidad

- Si un nuevo método se integra posteriormente al catálogo general, es obligatorio generar expediente conforme a analysis/METHOD_EVIDENCE_POLICY.md. Un informe privado para un usuario no es certificación pública.
- Consentimiento específico para que personal autorizado examine una APK privada y consentimiento separado para remitir contexto saneado a OpenAI/DeepSeek; minimizar acceso, controlar retención y permitir eliminación conforme a la política.
- La base de conocimientos de análisis se alimenta únicamente con scripts, patrones y fixtures sanos/autorizados; no incorporar automáticamente APK de clientes, secretos ni datos de terceros.
- El soporte humano realiza análisis en un entorno segregado, nunca dentro de los contenedores de producción con secretos VPS; no falsificar atestación ni burlar autenticación de terceros.

**Estado:** DOCUMENTADO, NO IMPLEMENTADO. Sin tickets, tablas, UI, rutas, despliegues o tareas automáticas. Esta ruta debe cubrirse en A2 (estados), A6 (panel) y A7 (derechos/contabilidad).

## 9. Decisiones pendientes del propietario

- Si el modo B debe costar igual o diferente del modo A; mantener política existente como referencia, no inventar un nuevo precio.
- Proveedor IA elegido, disponibilidad de API/billing y presupuesto máximo por trabajo.
- Consentimiento para transferir hallazgos saneados a proveedor externo.
- Límites de tamaño de APK, TTL de datos, disponibilidad de historial y reglas de reintento.
- Política de revisión humana (recomendada obligatoria) antes de incorporar scripts generados al catálogo productivo.
- Idiomas, formato de entrega (JSON + archivo ZIP con código; PDF opcional) y interfaz final aprobada mediante **vista previa interactiva en el chat** antes de programación.

**No hace falta resolver estos puntos en este chat. El proyecto queda documentado para retomarlo sin perder el diseño ni mezclarlo con la variante APK offline de SP-DECODE.**
