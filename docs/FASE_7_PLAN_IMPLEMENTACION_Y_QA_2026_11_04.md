# SP-DECODE — Fase 7: fases de implementación, dependencias, pruebas y criterios de salida

**Plan original: 2026-11-04 · Rama: feat/nuevas-integraciones · Estado actualizado 2026-11-06: F7-A0 PARCIAL con CI específico SUCCESS; F7-A1–F7-A9 DOCUMENTADAS / NO IMPLEMENTADAS.**

**Registro de continuidad, pendientes por fase y fallos de QA:** [FASE_7_SEGUIMIENTO_ESTADOS_Y_PENDIENTES_2026_11_06.md](FASE_7_SEGUIMIENTO_ESTADOS_Y_PENDIENTES_2026_11_06.md). La tabla de estados distingue hechos comprobados de requisitos de diseño.
Documento operativo complementario de:
- docs/FASE_7_CUENTAS_GOOGLE_PAGOS_Y_SOPORTE_APK_2026_11_04.md
- docs/FASE_7_ARQUITECTURA_SUSCRIPCIONES_CREDITOS_APK_2026_11_02.md
- docs/FASE_7_APK_AUTOANALISIS_DOS_SALIDAS_PENDING_2026_11_02.md
- analysis/METHOD_EVIDENCE_POLICY.md

## 1. Estrategia de implementación

No ejecutar en un único cambio masivo. Separar contratos de autenticación, base de datos, pagos, subida de APK, análisis, evidencias y UI. Ninguna fase debe romper decodificación actual, los catálogos Server VPN, exportación, legal consent o V1/V2 de SP-DECODE.

**Ningún commit de documentación implica habilitar funciones, crear proyectos Cloud/OAuth ni modificar VPS.** Mantener «Próximamente» y botones de compra deshabilitados hasta completar gates.

Dependencias principales:
- Identidad y datos de cuenta son prerrequisitos de créditos, compras, trabajos e historial.
- Ledger transaccional debe existir antes de aceptar cobros reales.
- Análisis estático + captura incremental de evidencia deben estar listos ANTES de recibir APK de clientes de pago.
- El panel humano y cierre sin cobro deben estar operativos ANTES del lanzamiento, no como función posterior opcional.
- Reembolsos, recibos, cancelaciones, account deletion y test de compra fallida son bloqueantes de producción.
- Modo B de generación IA es una extensión habilitable por separado; no prometer capacidad ni precio no aprobados.

**Seguimiento F7-A0 (2026-11-06):** [inventario y validador inicial](FASE_7_A0_INVENTARIO_Y_GATE_2026_11_06.md) registrados en feat/nuevas-integraciones. **Workflow F7-A0 validado**: [run 42303343370, intento 2, SUCCESS](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42303343370), 11/11 tests. Estado global A0 **PARCIAL**: aún faltan aprobaciones de herramientas, esquema, corpus y required check. **Validate SP-DECODE global no está verde**: [run 42303343453, intento 2, FAILURE](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42303343453), 13 fallos/3 errores/9 omitidas entre 1,206 tests; ver QA-01 en registro de continuidad.

## 2. Fases y entregables

### F7-A0 — Inventario y política de evidencias (alta complejidad técnica)

**Objetivo:** convertir los scripts/herramientas existentes en una base segura y reproducible.
- Auditar las rutas y los artefactos de analysis/, scripts/apk_analysis/ y herramientas compartidas.
- Inventariar herramienta, versión, licencia, checksum, arquitectura, dependencias y resultado verificable.
- Separar los métodos VERIFIED_REAL de pruebas sintéticas y hallazgos incompletos; evitar importar ejemplos no autorizados.
- Definir manifiesto versionado y esquema común para resultados/checkpoints, incluidos mensajes de error, nivel de evidencia y clasificación de datos.
- Crear, al momento de la futura implementación, gate CI que rechace altas de métodos sin documentos obligatorios; conservar compatibilidad con expedientes heredados.
- Validar límites de carga/análisis con APK/APKS propias o autorizadas.

**Salida:** inventario y contratos cerrados, suite básica de verificación ejecutada, licencias revisadas, herramientas de ejecución aprobadas y documentadas. No desplegar analizador con métodos no registrados.

### F7-A1 — Configuración de Google Cloud y acceso Google (complejidad media)

**Administrativa:**
- Elegir proyecto Google Cloud; configurar Google Auth Platform, SP-DECODE branding, soporte de dominio, sitio web, términos y privacidad verificables.
- Registrar OAuth Android con packageName/firmas de Play App Signing y Web client para validar ID tokens; cuentas de prueba y entorno separado de producción.
- Revisar verificación de marca, credenciales, secretos y restricciones de API.

**Backend:**
- Verificar Google ID token por sub/aud/iss/exp/nonce; resolver identidad, crear usuario o iniciar sesión propia.
- Sesión rotativa, logout, revocación, rate limits, error codes, auditoría con datos minimizados.
- Roles de admin separados de login de consumidores, MFA y elevación temporal.

**Android:**
- Credential Manager/Google Identity Services, selector de cuentas Google, validación visible, manejo de cuenta suspendida/sin conexión/cambio de cuenta.
- No activar autenticación Facebook/Discord, login por email+contraseña ni OTP de correo.

**Gate:** token con audiencia equivocada, caducado, alterado o reutilizado es rechazado; cuenta Google no verificada/ambiguo correo tratada según política; sin cuenta no se bloquean funciones gratuitas; Play App Signing reconocido; nombre real SP-DECODE visible tras configuración y verificación de marca.

### F7-A2 — Perfil, handle único, privacidad y My Account (complejidad media)

**Backend/schema:**
- accounts, identities, sessions, account_profile_events, consent_versions y deletion_requests;
- Unique DB sobre google sub y username canonical; migración idempotente y control de colisiones;
- Actualización independiente de display_name y username; límites, reautenticación, antifraude, reserva de nombres y auditoría;
- Perfil correo de Google read-only; sin editar dirección manualmente ni depender de correo como identificador permanente.

**UI:**
- Mi cuenta AMOLED: nombre visible arriba; debajo @handle y correo; créditos verificados; comprar créditos, mis análisis, historial, recibos, reembolsos, soporte, editar perfil, privacidad/eliminar cuenta, cerrar sesión.
- Inicio desde función comercial muestra solo «Continuar con Google», sin registro forzado a usuarios gratuitos.
- Edición de nombre visible no único y handle único, 409 con mensaje localizado, pending states sin datos ficticios.

**Gate:** colisiones concurrentes de username dan un único ganador; casefold/canonical correcto; no enumeración de cuentas; restaurar cuenta al reinstalar; solicitud de eliminación desde app y web, revocación de sesión y retenciones legales coherentes.

### F7-A3 — Ledger y reglas de créditos (complejidad alta por consistencia)

- Base de datos transaccional PostgreSQL o equivalente persistente: purchase_order, ledger inmutable, reservation, balance, movements, refunds, audit.
- Idempotency key por cuenta y operación, aislamiento transaccional/locking, reservas temporales con recuperador de huérfanas.
- API saldo oficial (nunca editable en cliente), recarga de pruebas diferenciada de dinero real, inyección de fallos/reintentos de DB.
- Reglas: reserva 1 crédito para trabajo A; cobrar solo al entregar resultado útil y conforme a la política aprobada; liberar al fallo definitivo. Para modo B esperar precio/plan aprobados.
- No alterar balances directamente desde panel: ajuste administrativo firmado y auditado con razón y aprobación.
- Separar crédito de pago/importe, producto consumible de suscripción y créditos restantes de reserva.

**Gate:** 100 solicitudes concurrentes con 1 crédito no generan doble gasto; una compra no da dos recargas; reintento no cobra dos veces; crash antes/después de reserva y entrega se recupera sin pérdida.

### F7-A4 — Servicio de APK y almacenamiento seguro (complejidad alta)

- Modelo de jobs + upload sessions, metadata, hashes, cuotas, autorización/consentimiento, estado y política de retención.
- Transferencia reanudable por fragmentos con integridad y autenticación. Evitar límite de 8 MB del decoder Cloud existente sin debilitar controles; diseñar una vía de archivos grandes explícita.
- Rechazar ZIP bomb, path traversal, payloads enormes, entradas malformadas y MIME/extensiones inconsistentes; tamaño, cuota, paralelismo configurables desde backend.
- Cifrado at rest con claves gestionadas servidor, aislamiento por cuenta/job, objetos con TTL, cuotas y acceso restringido.
- Redis puede mantener cola/locks, pero no almacena APK de larga duración.
- El selector Android no ejecuta ni instala la APK; mostrar consentimiento de envío y posible tratamiento humano.

**Gate:** archivo parcial nunca entra a analizar; resubida idempotente y SHA-256 validado; upload cancelado no cobra; usuario no accede al archivo de otro; borrado y retención probados.

### F7-A5 — Workers aislados, resultados y evidencia incremental (complejidad alta)

- Crear AnalysisOrchestrator, StaticApkAnalyzer, EvidenceIndex y ReportStore; ejecución en sandbox aislado sin secretos y con límites de CPU/RAM/IO/tiempo/red.
- Etapas estáticas de manifest, recursos, DEX, ELF, rutas de datos, herramientas seleccionadas; expresiones de evidencia OBSERVED/INFERRED/VERIFIED_REAL, etc.
- Persistencia incremental: cada etapa envía blobs con checksum a staging cifrado; publicación atómica de checkpoint; índices en DB; sanitización antes de exponer.
- Ante error por herramienta, timeout, salida corrupta, cierre worker o caída de red conservar último checkpoint y generar reason code.
- Artefactos parciales recuperables: manifest/provenance, file tree, logs saneados, outputs válidos, settings de herramientas, tests y errores; si falla inmediatamente, marcar sin evidencia técnica recuperable.
- Dos bundles: administrativo integral según permisos y user-safe filtrado cuando proceda. No incluir secretos ni datos de terceros sin revisión.

**Gate:** test forzado de crash en cada etapa conserva checkpoint anterior; checksum de ZIP y manifest correcto; no escape de sandbox ni fuga de secretos; clasificación de evidencia verídica; quota de disco no supera umbrales; errores son reproducibles sin ejecutar binarios no confiables en producción.

### F7-A6 — Panel Soporte APK, descargas temporales y entrega humana (complejidad media-alta)

- Bandeja Pendientes, En revisión, Esperando datos, Listos, Entregados, Sin solución; filtros por usuario/caso/fecha/modo.
- Caso muestra APK, SHA-256, fase exacta de fallo, razón, herramientas, checkpoints y evidencias. Botones: Descargar APK; Descargar evidencias ZIP; Ver evidencias; Solicitar datos; Subir resultado; Entregar resultado; Cerrar sin solución.
- Ticket de descarga temporal, scope por objeto/caso/actor; TTL corto, enlace preferiblemente de un solo uso, revocable; autenticación reforzada, MFA, auditoría y límites por usuario.
- Analizar fuera del VPS en VM aislada; no copiar APK privadas a repos, chats públicos ni telemetría. Política para copias locales, confidencialidad, IA externa con consentimiento.
- Subida de entregables por analista con inspección de zip, malware, secretos, licencia, modo contratado, evidencia de tests y revisión; notificación de disponibilidad al usuario.
- Reserva de crédito retenida durante investigación humana con política de límite y revisión; cierre sin solución libera la reserva; entrega válida confirma el cargo una sola vez.
- La pantalla de usuario oculta notas internas pero permite ver estatus y aportar información autorizada.

**Gate:** rol ajeno no puede generar ticket, ticket caducado/reutilizado falla, archivos fuera de caso no accesibles, descarga auditada; cancelación/solución y ledger idempotentes; comprobación de consentimientos y eliminación de copias.

### F7-A7 — Google Play Billing, notificaciones y conciliación (complejidad alta)

**Prerrequisitos administrativos:**
- Play Console: productos consumibles, ficha/microcopy, precio regional, cuentas tester, acceso Google Play Developer API, service account con mínimo permiso y Pub/Sub RTDN según configuración.
- Confirmar oferta y periodicidad de suscripción, reglas al cancelarla y créditos disponibles; no crear un SKU ficticio de suscripción.
- Configurar canal de producción sin introducir pasarelas externas en APK de Play salvo encaje jurídico/político verificado.

**Android y backend:**
- BillingClient oficial, flujo de compra con cuenta iniciada y detalles reales del producto; compras pendientes/restauración, error/backoff.
- API verifica token con Play, compra PURCHASED, SKU, orderId, cantidad, asociación a cuenta, idempotencia; asienta crédito y reconoce/consume compra cuando corresponda.
- RTDN y polling de reconciliación periódica, API de pedidos anulados, contracargos/chargebacks, duplicados/replays, revocación.
- No usar verificaciones de compra en Kotlin/C++ como autoridad financiera ni permitir saldo manual por almacenamiento local.

**Gate:** pruebas con licencias Play, compra cancelada/pending, mismos tokens repetidos, compra de otra cuenta, devolución posterior a gasto, y reconciliación después de caídas. Asegurar que no se cobran tarjetas reales durante QA sin control explícito.

### F7-A8 — Historial, recibos, solicitudes y reembolsos (complejidad media-alta)

- UI «Mis compras», comprobante PDF informativo, producto, fecha, referencia, importe y moneda real, créditos, estado; historial de movimientos y trabajos relacionados.
- Separar recibo Google de comprobante interno y de factura fiscal. Factura únicamente cuando se configure emisor y procedimiento legal; jurisdicción/CFDI sujetos a revisión.
- Solicitar devolución de crédito por servicio fallido y reembolso monetario de pedido son vías distintas, con comunicaciones claras y estados auditables.
- Panel de solicitudes con evidencia de resultado, aprobación por rol, consulta Play y ejecución oficial del reembolso; nunca afirmar éxito hasta confirmación proveedor.
- Revisión de resultado exitoso: regla general de servicio prestado, **sin negación absoluta** de reembolso. Google, derechos legales, errores de cobro, fraude y defectos pueden imponer excepciones. Publicar política revisada.
- Email transaccional mediante dominio autenticado (no OTP para Google Sign-In); evitar adjuntar secretos y datos de APK.

**Gate:** refund en Play actualiza ledger y evita doble devolución; rechazos quedan justificados; chargeback simultáneo no produce doble reverso; emails no exponen información sensible; cifras y monedas se concilian.

### F7-A9 — Integración Android final, localizaciones y despliegue progresivo (complejidad media-alta)

- Reemplazar «Próximamente» únicamente detrás de feature flags del servidor tras pasar gates; mantener importador VPN actual intacto.
- Pantallas AMOLED completas Mi cuenta, Creditos, Analizar APK, Mis análisis, estado, entregar/descargar, historial, comprobantes, soporte y privacidad.
- Localización de los **14 idiomas** existentes, RTL, accesibilidad, font scale, talkback, tablet/compact screen, bajo ancho de banda.
- Modal de compra/confirmación sin precios inventados; estado de los trabajos y análisis real, no porcentaje ficticio.
- Integridad Cloud V2/Play y permisos de descarga, cache/no-backup de datos sensibles; manejo offline limitado a último estado no autoritativo.
- Beta cerrada, métricas agregadas sin datos personales, observabilidad, cuota, rate limits y circuit breakers; canary y rollback que preservan saldos.

**Gate:** QA e2e en dispositivo firmado Play, cuenta real de prueba, sandbox, red lenta, reinicios, error de worker, revisión humana, reembolso, exportación/eliminación; documentación legal y ficha Data Safety aprobadas. Ninguna credencial en APK ni en commit.

## 3. Tabla de dependencias y esfuerzo relativo

| Fase | Depende de | Esfuerzo relativo | Riesgo dominante |
|---|---|---|---|
| A0 | Evidencias existentes | Alto | Herramientas/documentación no reproducibles |
| A1 | Google Cloud, dominio, firmas | Medio | Configuración OAuth o identidad incorrecta |
| A2 | A1 | Medio | Conflicto de usernames, privacidad |
| A3 | A1/A2 | Alto | Doble gasto / saldo inconsistente |
| A4 | A1/A3 | Alto | Upload grande, abuso de recursos |
| A5 | A0/A4 | Alto | Seguridad de análisis no confiable |
| A6 | A3/A4/A5 | Medio-alto | Filtración de APK/evidencia, entrega indebida |
| A7 | A1/A3 + Play Console | Alto | Pago falsificado, reembolso, conciliación |
| A8 | A2/A3/A7 | Medio-alto | Reglas comerciales, fiscales y contables |
| A9 | Todas las anteriores | Medio-alto | Regresiones, publicación e integración |

**Valoración:** proyecto completo de complejidad ALTA; no es un cambio puntual de interfaz y no puede tratarse como una sola fase trivial. Se puede dividir y validar, con backend operativo y créditos de prueba antes de habilitar dinero real. El tiempo real dependerá de acceso a Play Console/Cloud, preparación de herramientas, infraestructura, resultados de QA y revisión legal. No se fija fecha hasta aprobar hitos y alcance.

## 4. Criterios de aceptación detallados de extremo a extremo

### Autenticación / perfil
1. Iniciar con Google 1, comprar créditos (en pruebas) y reiniciar: misma cuenta/saldo; iniciar Google 2 no revela compras de Google 1.
2. Modificar display_name sin afectar sub/email; cambiar username de forma exclusiva, incluyendo dos usuarios intentando mismo handle simultáneamente.
3. Error de red/invalidez de token no inicia sesión; logout revoca sesión; free decoding sigue utilizable.
4. Account deletion desde app/web elimina datos correspondientes y conserva solo lo legalmente necesario según política.

### Compras / saldos / reembolsos
1. Compra PENDING no acredita; PURCHASED verificada acredita una vez y es consumida/reconocida; mismo token reintentado es idempotente.
2. Modificar saldo local o petición para forzar créditos/privilegios no autoriza análisis.
3. Tras reembolso Google, ajustar saldo de forma auditable; si ya estaba consumido, aplicar política de resolución sin reescribir historial.
4. Compra valida y job fallido no consume; reembolso monetario se distingue del reintegro de crédito; las dos rutas no crean crédito+dinero duplicados.
5. Consulta de compra/recibo de otra cuenta es denegada; no se muestran tokens ni datos fiscales ajenos.

### Análisis / evidencias / soporte
1. Subir APK autorizada de prueba por chunks, verificar hash, reservar crédito y generar informe A; cobrar únicamente tras entrega válida.
2. Cortar worker tras checkpoint 2: la admin descarga APK y evidencias ZIP con outputs de checkpoint 1/2, manifest, hashes, error, tools version y timestamps; no hay artefactos inexistentes inventados.
3. Permisos: usuario ajeno no puede descargar evidencia ni APK; admin con rol + MFA obtiene ticket breve, ticket caduca/revoca y auditoría registra descarga.
4. Analista procesa en VM fuera de producción y entrega informe con provenance; backend verifica identidad y entregables antes de cerrar.
5. Si soporte humano no logra producir resultado, se libera crédito; reintento del mismo job no cobra dos veces.
6. Modo B exige proceso y tests propios; prueba sintética no se etiqueta «método real confirmado».
7. Inputs con ZIP bomb/path traversal/credenciales en logs se rechazan/sanitizan; no se ejecutan APK desconocidas en production.

### Operación / continuidad
1. Todos los endpoints con autorización por account_id o rol server side, límites y audit.
2. Desplegar en rama/ruta aprobada, nunca fusionar automáticamente a main; revisar workflows existentes antes de merge.
3. Pruebas unitarias, integración, instrumentación Android, seguridad, carga y regresión; no dar por realizado un test que no se ejecutó.
4. Observabilidad no captura documentos privados, credenciales, tokens ni contenido de APK.
5. Rollback de un despliegue no elimina cuentas, órdenes o créditos ni deja reservas inválidas.

## 5. Configuración externa que exigirá acción del propietario

**Google Auth Platform:** proyecto Cloud, nombre/logotipo verificados SP-DECODE, dominio y políticas públicas, email soporte, identidad del desarrollador y clientes OAuth Android/Web, huellas reales Play App Signing.

**Google Play Console:** productos/consumibles, precio por país, testers, Google Play Developer API, permiso de lectura/validación y operación de refunds, notificaciones RTDN/PubSub; servicio de suscripciones a definir.

**Correo del dominio:** dirección de soporte existente comprobada, SPF/DKIM/DMARC y proveedor SMTP/API de notificaciones si se decide enviar avisos/recibos; sin códigos OTP de login.

**VPS/Cloud:** storage cifrado, worker de análisis segregado, colas, bases transaccionales, backups, audit y plan de retención de APK/evidencias; valores de tamaño y costo medidos con pruebas reales.

**Legal:** aceptación de subida de APK, tratamiento por humanos/IA, derechos de autor y legitimidad de muestras, política reembolso, privacidad, términos, eliminación de cuenta, emisor de factura cuando corresponda.

Todas las credenciales deberán quedar en secret manager o configuración de servidor protegida; **ninguna credencial real ni token se solicita/guarda en estos documentos**.

## 6. Decisiones a presentar antes de ejecutar cada fase

- Usuarios: nombre visible y username únicos sí; reglas definitivas de cambio/longitud a aprobar.
- Suscripción: precio, duración, derechos y su relación con créditos todavía abiertos; **mantener contrato previo sin inventar precios**.
- Modo B: si estará disponible desde el lanzamiento, tarifa, costo operativo, proveedor LLM, validación real y derechos de explotación.
- Política comercial: plazo de atención/reintegro, gestión de resultados parciales, trabajo duplicado, refund por Play, factura y responsable tributario.
- Retención: APK original, evidencia parcial, informes, logs, copias administradores locales, enlaces de descarga y eliminación.
- Capacidad: tamaño máximo APK/APKS, cuotas diarias, concurrencia, número de reintentos y límite de soporte manual.
- UI: revisar vista previa AMOLED de Mi cuenta y Soporte APK en chat antes de escribir Compose.

**No comenzar cambios ejecutables, compras reales, configuración OAuth, envíos de correo, despliegues ni creación de ramas desde este documento sin orden explícita del propietario.**

## 7. Fuentes oficiales para verificar antes del desarrollo

- https://developer.android.com/identity/sign-in/credential-manager-siwg-implementation
- https://developers.google.com/identity/gsi/web/guides/verify-google-id-token
- https://developers.google.com/identity/verification/authentication-policy-compliance
- https://developer.android.com/google/play/billing
- https://developers.google.com/android-publisher/voided-purchases
- https://support.google.com/googleplay/android-developer/answer/2741495
- https://support.google.com/googleplay/android-developer/answer/13327111
