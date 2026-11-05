# SP-DECODE — Fase 7: cuentas Google, compras, reembolsos, evidencias y soporte APK

**Especificación integral — 2026-11-04. Rama de trabajo: feat/nuevas-integraciones.**
**Estado: DOCUMENTACIÓN / FUTURA IMPLEMENTACIÓN.** Este cambio documental NO habilita inicio de sesión, compras, análisis, facturación ni descargas de APK.

**Referencias obligatorias que se complementan, no reemplazan:**
- docs/FASE_7_ARQUITECTURA_SUSCRIPCIONES_CREDITOS_APK_2026_11_02.md (suscripción + créditos, ledger y contrato comercial).
- docs/FASE_7_APK_AUTOANALISIS_DOS_SALIDAS_PENDING_2026_11_02.md (modos A y B, scripts reutilizables, IA, sandbox y soporte humano).
- analysis/METHOD_EVIDENCE_POLICY.md (evidencias y herramientas reproducibles, cumplimiento estricto).
- docs/android/APK_CREDITS_FEEDBACK_AMOLED_2026_11_02.md (UI AMOLED existente, 14 idiomas).
- docs/FASE_7_PLAN_IMPLEMENTACION_Y_QA_2026_11_04.md (fases y controles de salida de cada etapa).

## 0. Decisiones y alcance

1. **Proveedor único de inicio de sesión para el lanzamiento: Google.** No integrar Facebook, Discord, número telefónico, usuario+contraseña ni códigos OTP por correo como segunda vía de autenticación.
2. La cuenta **NO será necesaria para usar gratuitamente SP-DECODE** (decodificación actual, formatos, ajustes y catálogo). Sí se requerirá para comprar créditos, ver pedidos/recibos y solicitar/ver análisis APK.
3. Se crean **dos campos de nombre distintos**, editables por el usuario: nombre visible (no único) y nombre de usuario o handle (único, sin repeticiones ignorando mayúsculas/minúsculas). El correo obtenido de Google es un dato de identidad distinto, no el handle.
4. Un usuario podrá solicitar devolución de un crédito por un trabajo fallido y, por separado, solicitar un **reembolso monetario de la compra**. La aprobación de un reembolso de dinero requiere verificación del pedido, política de Google Play, derechos del consumidor y autorización administrativa. Nunca prometer que una compra ya utilizada no puede reembolsarse por ninguna circunstancia.
5. La versión comercial distribuida mediante Play usará **Google Play Billing**, con verificación y ledger EXCLUSIVAMENTE en servidor. Ninguna variable en Kotlin/C++ ni preferencia local acredita saldo. Las alternativas de pagos exteriores requieren evaluación de políticas por canal/país y quedan fuera del MVP.
6. Conservamos los **dos modos de análisis**: A informe y evidencias; B informe + proyecto de código y pruebas (si está disponible y se puede validar). Un resultado no se declara verificado por haberlo generado una IA.
7. Cuando el análisis no termina satisfactoriamente, el servidor conserva **las evidencias parciales obtenidas antes del error**, genera un caso para Soporte APK y permite que personal autorizado descargue tanto la APK original como esas evidencias para investigar **fuera del servidor**.
8. El módulo Fase 7 permanece en «Próximamente» hasta superar todas las puertas de QA, privacidad y pagos. No modificar la versión/build ni la lógica existente de Cloud.
9. Precio de referencia solicitado previamente: **USD 4 por crédito**, **1 crédito por análisis tipo A**; usar siempre el precio local real devuelto por Play. Precio del modo B, suscripción (precio/periodicidad/beneficios), paquetes, caducidad y reglas de parcial siguen **pendientes de aprobación**, según documentos de base. No crear productos comerciales inventados.

## 1. Identidad: solo Google y cuenta interna SP-DECODE

### 1.1. Configuración necesaria en Google Cloud

- Crear/usar proyecto Google Cloud bajo control del desarrollador; configurar **Google Auth Platform / Branding** con nombre exacto **SP-DECODE**, logotipo permitido, correo de soporte propio del dominio, página principal y URL reales de privacidad y términos.
- Comprobar/verificar dominio propio y publicar branding según requisitos actuales de Google; habilitar audiencia externa y efectuar las revisiones solicitadas. No prometer que nombre/logo aparecerán en todos los dispositivos antes de la verificación.
- Registrar cliente OAuth **Android** para packageName real y huellas SHA-1/SHA-256 de las firmas aplicables (Google Play App Signing, y QA solo para entornos de prueba). Registrar además un cliente OAuth **Web** usado como serverClientId/audience de validación backend. No inventar nombres de paquetes ni fingerprints; leer configuración efectiva.
- Android: usar **Credential Manager + Sign in with Google**, con botón oficial, selector de cuentas, nonce impredecible, autorización mínima (identidad básica, email, perfil), reintento y cierre de sesión. No pedir permisos de Gmail, Drive ni acceso a contactos.
- API: recibir ID token por la ruta formal de autenticación, comprobar firma mediante claves públicas de Google, **aud**, **iss**, **exp**, nonce y demás controles pertinentes; comprobar políticas sobre email y email_verified según la naturaleza del correo. Vincular la identidad a Google **sub** (ID estable), no email ni nombre. Al registrar/iniciar, emitir sesión propia corta/renovable, con rotación, revocación y vinculación al dispositivo/riesgo cuando corresponda. No reutilizar un ID token como sesión permanente.
- La cuenta administrativa NO se concede por tener una dirección concreta ni por editar un handle. Roles de administrador asignados explícitamente fuera de endpoints públicos con MFA fuerte.

### 1.2. Modelo de perfil

Campos conceptuales:
- account_id: UUID/ULID interno, inmutable, clave de asociación a compras, trabajos y solicitudes;
- provider: google; provider_subject: sub, único e inmutable por cuenta Google;
- email: valor verificado por la identidad, mostrado en cuenta; actualización solo mediante reautenticación válida, nunca editando texto;
- display_name: nombre visible EDITABLE, **no único**; inicializado desde claim name de Google, recortado y sanitizado;
- username: handle público EDITABLE, **único por canonicalización** (NFKC/normalización definida, casefold, anti-confusables según política); índice UNIQUE en DB, no solo comprobación Android;
- avatar: foto Google u opción del usuario si se aprueba; nunca URL arbitraria para peticiones internas;
- roles, created_at, last_login_at, privacy_consent_version, disabled_at, deletion_requested_at.

**Reglas de producto propuestas para username (a revisar antes de implementar):** 3-24 caracteres ASCII minúscula, números y guion bajo; empieza con letra; sin espacios, puntos, @ almacenada ni caracteres de control; reservar admin, support, spdecode y marcas del sistema. Cambios con reautenticación y limitación de frecuencia para evitar suplantación, enumeración y ocupación masiva. El alias antiguo queda temporalmente reservado o redirigido según política. Nombre visible acepta Unicode con límite, filtrado de controles y moderación de impersonación. El usuario podrá cambiar nombre visible y handle por separado. En el encabezado de Mi cuenta se muestra preferentemente **nombre visible** y debajo **correo o @username**, con opción de mostrar ambos en datos personales.

### 1.3. Cuenta y privacidad

- Primera entrada al módulo de pago: explicar inicio con Google y tratamiento de datos; **no forzar** registro a usuarios de funciones gratuitas.
- Flujo de sesión expirada y restauración de compras por misma cuenta Google; el saldo vive en el servidor, no en el dispositivo.
- «Mi cuenta → Privacidad → Solicitar eliminación de cuenta» dentro de Android y una página externa propia del dominio que permita solicitar eliminación; informar qué datos se borran y cuáles pueden conservarse por obligación contable/legal, cuánto tiempo y por qué. Revocar sesiones, eliminar APK/evidencias según política y anonimizar registros obligatorios.
- Exportación de datos de cuenta e historial, cierre de sesión y gestión de consentimientos; información de soporte y tratamiento de APK.
- Nunca almacenar contraseña Google, tokens OAuth en logs, tokens Play en recibos ni datos de pago bancario.

### 1.4. Correo corporativo y códigos de verificación

**No se necesita un OTP enviado por nosotros para «Iniciar sesión con Google».** Google autentica la identidad; el backend verifica el ID token. Enviar un código adicional por correo desde el dominio para cada login añade fricción, puntos de fallo y no debe reemplazar a Google Sign-In.

El buzón de soporte del dominio sí es adecuado para:
- recibir solicitudes de contacto y permitir responder;
- figurar como email de asistencia en Google Auth Platform y Play Console;
- enviar avisos transaccionales de compra registrada, caso aceptado, evidencia adicional requerida y resultado disponible (sin adjuntar APK privada, enlaces eternos, claves ni resultados confidenciales);
- enviar comprobantes comerciales internos o avisos de cambio de estado, respetando preferencias y obligaciones de entrega.

Si en el futuro se implementa OTP para **operaciones extraordinarias**, usar buzón transaccional separado (no el inbox humano de soporte), proveedor de correo autenticado SPF/DKIM/DMARC, límites de envíos, duración breve, un solo uso, anti-replay, anti-enumeración y monitorización; exige nuevo diseño/decisión. En esta fase NO se habilita OTP.

## 2. Maqueta textual aprobable: «Mi cuenta» (AMOLED)

Mantener negro puro, tarjetas gris oscuro, textos blancos/grises, bordes/esquinas y botones del tema actual; todas las nuevas pantallas usan el mismo sistema de diseño y los 14 idiomas.

### Vista logueado

    Mi cuenta                                      [avatar]
    ───────────────────────────────────────────────────
    Nombre visible                                  Editar
    @usuario_unico
    persona@correo-ejemplo.com

    Créditos disponibles                                 3
    [Comprar créditos]

    Mis análisis de APK
    Historial de compras
    Recibos y comprobantes
    Solicitudes de reembolso
    Soporte de APK / Mis solicitudes
    Ajustes de perfil
    Privacidad y eliminar cuenta
    Cerrar sesión

Nota: correo/nombre/3 créditos son marcadores de maqueta. Mostrar datos SOLO obtenidos de sesión autenticada y APIs verificadas; nunca números ficticios en producción. Si se elige mostrar correo debajo del nombre, el handle permanece accesible sin duplicar títulos o información innecesaria.

### Editar perfil

    Editar perfil
    Nombre visible:      [Ghost Developer        ]
    Nombre de usuario:   [ghost_developer        ]
    Correo Google:       persona@correo-ejemplo.com  [solo lectura]
    [Guardar cambios]     [Cancelar]

Comprobar disponibilidad de handle en servidor al guardar, errores de colisión (409), límites y auditoría; evitar enumerar correos de otras cuentas.

### Sin sesión

    Mi cuenta
    Inicia sesión con Google para comprar créditos,
    revisar tus pedidos y administrar los análisis.
    [Continuar con Google]

Sin bloquear las pantallas gratuitas. El diseño de pago nunca debe imponer inicio de sesión de otras redes sociales.

## 3. Pagos Google Play, verificación y contabilidad

### 3.1. Productos y cobro

- Producto de compra única **consumible** para 1 crédito de análisis A (SKU ya propuesto en documentación previa: spdecode_apk_credit_1), sujeto a validación del producto final en Play Console.
- Suscripción de acceso al módulo prevista en Fase 7; **precio, periodo, derechos, planes y tratamiento de créditos al cancelar están pendientes**. No activar hasta aprobación; no asumir que USD 4 es el precio de una suscripción.
- Solo si producto está disponible, cuenta autenticada y condiciones aceptadas: Android abre BillingClient; presenta precio localizado real de Google Play, no literal universal USD.
- App envía prueba/token al servidor. Backend verifica con Google Play Developer API y comprueba package, SKU, estado PURCHASED, cuenta enlazada, no duplicación, orden, cantidad y coherencia. Sólo entonces registra un asiento de compra y acredita créditos mediante transacción.
- Consumir/reconocer el producto según las reglas de Play dentro del plazo aplicable; procesar compras PENDING sin otorgar acceso hasta que sean confirmadas. Usar RTDN + reconciliación periódica idempotente + Voided Purchases para notificaciones de reembolsos, chargebacks y revocaciones.
- El servidor decide el saldo, reservas y análisis. Una APK modificada que simule Billing o incremente saldo visual no obtiene crédito. Play Integrity y HPKE siguen como defensas adicionales, no reemplazan el ledger.
- Las claves de servicio/Google Cloud permanecen exclusivamente en backend, con acceso mínimo, rotación, sin incluidas en APK, GitHub o panel visible.

### 3.2. Entidades contables mínimas (no SQL real)

- purchase_order: account_id, order_id Google, product_id, purchase_token_hash/referencia cifrada, moneda, monto realmente reportado, cantidad, estado, created/updated, provider=google_play.
- credit_ledger: asiento inmutable con account_id, delta, tipo (PURCHASE, RESERVE, RELEASE, SPEND, REFUND_ADJUSTMENT, ADMIN_CORRECTION), referencia externa, idempotency_key y actor.
- credit_reservation: account_id, job_id, estado, vencimiento y versión para exclusión.
- payment_event: eventos RTDN y reconciliación, sin duplicados ni datos bancarios.
- refund_request: account_id, order_id, job_id opcional, reason_code, solicitud, estado, respuesta admin, decisión Google, auditoría.
- receipt: pedido, emisor, folio interno, fecha, importe, moneda y crédito acreditado/revocado; sin datos sensibles.

**Invariantes:** una compra no se acredita dos veces; una reserva no consume dos veces; la concurrencia no vuelve negativo el saldo gastable; la compra debe estar vinculada al sujeto correcto; una revocación usa asientos compensatorios, nunca modifica la historia silenciosamente.

### 3.3. Recibos, comprobantes y facturas

En «Mis compras», mostrar pedido, fecha, producto, importe y moneda real, estado, créditos y acciones:
- «Ver compra en Google Play» / instrucción de consultar recibo oficial;
- «Descargar comprobante SP-DECODE» (PDF informativo y referencia del pedido, no reemplaza documento fiscal);
- «Solicitar factura», **solo si existe emisor fiscal responsable y proceso legal configurado**; definir jurisdicción, requisitos, plazos, responsable, SAT/CFDI cuando aplique y manejo seguro de datos fiscales.
- «Solicitar reembolso» para abrir caso con orden y motivo. No simular reembolso automático exitoso por pulsar un botón.

El recibo oficial de Google Play y el registro interno son documentos diferentes. No afirmar que nuestro PDF equivale a CFDI o factura legal. La cuenta conservará historial de ajustes de créditos y reembolsos.

## 4. Reintegros de crédito y reembolsos de dinero

**Dos procesos completamente distintos:**

**A. Reintegro de crédito por análisis fallido**: si un trabajo no aporta el entregable prometido tras intentos limitados y revisión humana, el servidor libera la reserva. Si el cargo se había confirmado por error, crea asiento inverso auditable. Esto NO envía dinero de vuelta a Google Play. El usuario puede iniciar un trabajo nuevo usando ese crédito.

**B. Reembolso monetario del pedido**: el usuario presenta solicitud de devolución del importe pagado. Se revisan el pedido original y su estado en Play, créditos restantes, trabajos/entregas, fallo imputable al servicio, normas territoriales y política de reembolsos. Un admin autorizado utiliza la función oficial de Google Play Console/API para tramitar cuando proceda; el backend refleja el resultado, revoca derechos aplicables y registra ajustes. No aceptar un campo del cliente «refund=true» como resultado monetario.

**Política de servicio propuesta (sujeta a revisión legal y aprobación comercial):**
1. Caso sin resultado útil definitivo: priorizar reintegro íntegro del crédito. Si solicita dinero, evaluar el reembolso del pedido asociado y si existen créditos ya consumidos.
2. Pedido pagado pero no acreditado, compra duplicada o fallo persistente de entrega: investigar y ofrecer restitución/reembolso correspondiente.
3. Resultado ya entregado y válido: el servicio normalmente se considera prestado y no se ofrece devolución voluntaria ordinaria simplemente por haber obtenido el producto; **NO establecer prohibición absoluta**: Google puede reembolsar, y derechos legales, compras no autorizadas, defecto real o disputas pueden requerir otra resolución.
4. Si una compra cubre varios créditos, separar cantidad usada y restante; no conceder simultáneamente reintegro de crédito y dinero sin compensación idempotente.
5. Reembolso procesado por Google/chargeback después de usar crédito: evento compensatorio, revisión y posible bloqueo de nuevas reservas por riesgo; no borrar resultados entregados o datos obligatorios sin base legal y política transparente.
6. Rechazar o aprobar con motivo específico, notificar al usuario, permitir revisión/disputa y conservar auditoría. No permitir que una regla automática sin evidencia cierre casos controvertidos.
7. La política pública debe explicar requisitos, tratamiento de entregas parciales, derecho de desistimiento cuando aplique, plazos según plataforma y cómo solicitar soporte. No fijar una regla «sin reembolsos nunca» contraria a Google o a legislación.

**Estados:** REQUESTED → UNDER_REVIEW → APPROVED/REJECTED → SUBMITTED_TO_PLAY → REFUNDED/FAILED → LEDGER_RECONCILED. Resolver también refund recibido sin solicitud local, notificaciones fuera de orden y cargos anulados.

## 5. Análisis automático y soporte APK con evidencias recuperables

### 5.1. Flujo automático

Usuario autentica → elige modo A/B → acepta condiciones de análisis/cesión de archivo → preflight + cuota → reserva de crédito → upload cifrado/reanudable → cola separada → herramientas estáticas registradas → observaciones y artefactos parciales → validación → entrega o escalamiento.

Nunca ejecutar APK desconocida en contenedores de producción. En modo A producir informe realmente observado; modo B usa IA solo para propuesta de código sanitizada + pruebas en sandbox y nunca publicar código automáticamente.

### 5.2. Evidencia DURANTE el trabajo y AL FALLAR (nuevo requisito obligatorio)

Cada etapa del worker escribe puntos de control de evidencia a un **almacén privado por job**, no a logs de contenedor efímeros. La captura sucede incrementalmente, *antes* del punto potencial de fallo. Si el worker cae o expira un timeout, el caso conserva la última evidencia íntegra ya confirmada.

Paquete privado «Evidencias previas al fallo», con manifest firmado/autenticado:
- job_id, account_id pseudónimo, paquete/build observado, SHA-256 de APK e inputs autorizados, versiones de herramientas/scripts y commit del analizador;
- etapas ejecutadas, timestamps, comandos reproducibles sanitizados, exit codes, tiempos, límites y reason codes (sin tokens ni credenciales);
- APK_MANIFEST_SUMMARY.json, DEX/ELF/resource inventory, file tree con límites, detected_formats.json, findings.json y results.json PARCIALES según existan; NO marcar campos ausentes como verificados;
- logs de análisis **redactados**, stdout/stderr acotados y clasificados, trazas de excepción sin datos personales/secretos, errores y último checkpoint;
- catálogo de evidencias con SHA-256, tamaño, MIME, clasificación, origen y estado (OBSERVED, INFERRED, VERIFIED_REAL, VERIFIED_SYNTHETIC, FAILED, UNKNOWN);
- referencias a herramientas de analysis/, scripts realmente usados, VERSION/lockfile y pasos de reproducción; no duplicar APK en Git;
- README para reproducir en entorno aislado, limitaciones y motivos de fallo; si no hubo resultados, indicar «sin evidencia recuperable».

**Integridad y seguridad:** tamaño máximo por archivo y bundle, antivirus/ZIP-bomb checks, sanitización de paths, prohibición de incluir secrets, passwords, claves de terceros, token HPKE, tokens OAuth o logs sin redacción. Los propios inputs pueden contener secretos no reconocidos: acceso mínimo y aprobación de confidencialidad; jamás adjuntar evidencia privada a emails o al repositorio público. Fallos que ocurran antes de la primera extracción no garantizan más que metadatos de recepción y error.

Persistencia separada de la cola: almacenamiento de objetos cifrado con versiones/checkpoints y hashes, escritura atómica/confirmación de manifest; job y referencia de blob guardados transaccionalmente; retención y destrucción seguras. Control explícito de costos/espacio (cuotas). No usar Redis como almacén permanente de APK.

### 5.3. Escalamiento y panel «Soporte APK»

Estados propuestos: QUEUED → ANALYZING → NEEDS_HUMAN → HUMAN_IN_PROGRESS → WAITING_USER_INPUT / READY_FOR_DELIVERY → DELIVERED; alternativas FAILED_FINAL, CANCELLED y EXPIRED. El cambio automático a NEEDS_HUMAN debe conservar evidencia ya validada y motivo del escalamiento.

**Vista administrativa aprobada, AMOLED consistente con el panel existente:**

    Soporte APK
    Pendientes | En revisión | Esperando datos | Entregados | No resueltos

    Caso #APK-1042                   Revisión humana
    Archivo: aplicacion.apk
    Modo solicitado: Informe / Informe + código
    APK SHA-256: ...                  Fecha de solicitud: ...
    Error automático: [código y fase]      Checkpoints: N

    [Descargar APK]      [Descargar evidencias ZIP]
    [Ver evidencias]     [Historial técnico]

    Nota interna / solicitud de muestra adicional
    [Adjuntar resultado] [Validar entregables] [Entregar resultado]
    [Marcar sin solución y liberar crédito]

La maqueta contiene marcadores; no son botones activos ni casos reales. No mostrar al usuario notas internas, secretos, URL de objetos, hashes de tokens ni rutas del VPS.

**Descarga para trabajar fuera del servidor**:
1. Administrador inicia sesión con rol revisable y segundo factor, abre caso asignado; autorización por rol y caso comprobada en servidor.
2. Pulsar «Descargar APK» o «Descargar evidencias ZIP» hace que el servidor emita un enlace temporal de alcance mínimo (objeto+caso+auditoría), preferentemente de un solo uso, caducidad breve y revocación. Nunca URL permanente de S3/VPS ni incluirla en la notificación al usuario.
3. El servidor entrega objetos cifrados en reposo por HTTPS; si se permite reanudación se conserva autorización por fragmento. Se registra actor, caso, objeto, fecha, resultado y hash esperado.
4. Administrador descarga a equipo/VM de análisis **aislado de producción**. No instalar APK desconocida en el teléfono personal ni ejecutar binarios en VPS con secretos. Las copias locales deben estar cifradas, tener acceso restringido y eliminarse tras el caso, de acuerdo con política y obligaciones legales.
5. Analista puede usar herramientas propias y asistente de IA solo si el consentimiento y la clasificación de datos lo permiten; no subir APK ni hallazgos privados a un tercero automáticamente.
6. Al finalizar, subir informe y/o proyecto de código, evidencias nuevas, hashes y resultado de tests. Validación de paquete de salida (antimalware, secretos, licencia, tamaño y correspondencia con modo A/B).
7. «Entregar resultado» requiere confirmación explícita de archivos, revisión y estado de cobro. Entrega privada e idempotente al dueño del caso; notificación solo con referencia, sin adjunto sensible. Confirmar crédito solo por entregable útil acordado.

**Panel muestra** número de checkpoints parciales, fase de fallo, versiones de herramientas, archivos generados, timestamps y error redactado para reducir rehacer todo el análisis.

### 5.4. Usuario y seguimiento

En «Mis análisis» mostrar el estado entendible: «En cola», «Analizando», «En revisión humana», «Necesitamos información», «Resultado disponible» o «No se pudo resolver». Al solicitar datos adicionales, pedir solo muestras autorizadas y limitar intentos sin cobros repetidos.

La descarga de evidencias técnicas brutas **no se habilita al usuario por defecto**: pueden contener información sensible y notas internas; entregar el informe convenido y una versión pública de evidencias depurada cuando corresponda. Admin sí puede descargar el bundle íntegro permitido.

## 6. API futura: contratos lógicos no desplegados

**Autenticación/perfil**
- POST /account/auth/google: token + nonce/verificación; emitir sesión.
- GET /account/me: perfil, correo, handle, rol expuesto mínimo, saldo confirmado.
- PATCH /account/me: display_name y username únicos; reautenticación según riesgo.
- POST /account/logout, POST /account/deletion-request.
- GET /account/data-export; GET /account/purchases y recibos autorizados.

**Compras/contabilidad**
- POST /billing/google/verify: token de compra; idempotencia estricta y vinculación a account_id.
- GET /billing/products y /billing/ledger; POST /billing/refund-requests; GET /billing/refund-requests.
- Endpoint backend exclusivo para RTDN/PubSub, con autenticación y verificaciones del pedido en Google; no exponer al cliente.
- Operaciones de reembolso monetario solo admin con autorización reforzada, auditoría y procesamiento Google oficial.

**Análisis**
- POST /apk-jobs/preflight, POST /apk-jobs, upload por partes validado, GET /apk-jobs/:id, GET /apk-jobs/:id/results, POST /apk-jobs/:id/cancel, GET /apk-jobs/:id/events.
- Los límites de tamaño APK, retención y presigned downloads se fijarán tras pruebas de capacidad; no inventar números de producción.
- Las rutas arriba son **ilustrativas**, no son endpoints ya disponibles ni deben reemplazar las operaciones existentes HPKE C++/JNI sin una revisión formal del protocolo.

**Administración**
- GET /admin/apk-cases, GET /admin/apk-cases/:id, POST /admin/apk-cases/:id/download-ticket (type=apk|evidence), POST /admin/apk-cases/:id/upload-delivery, POST /admin/apk-cases/:id/resolve, POST /admin/apk-cases/:id/request-more-info.
- Autorización server-side, descargas auditadas, roles específicos, protección CSRF para panel web, rate limits y políticas de eliminación. No compartir enlaces entre cuentas.

## 7. Seguridad y cumplimiento transversal

- Mantener HPKE Cloud V2, PoP, Play Integrity y controles existentes donde apliquen. Para archivos grandes evaluar protocolo de carga por fragmentos con garantías equivalentes (autenticación, TLS, integridad, límites, reanudación), sin pasar arbitrariamente APK a un endpoint antiguo.
- Android usa C++ para validación y comunicación sensible de acuerdo con la arquitectura prevista; los adaptadores obligatorios de Credential Manager/Billing siguen siendo Android SDK, **pero autorización de cuentas, compras, créditos, descarga y trabajos se decide en backend**.
- Aislar almacenamiento/colas/workers/panel: sin claves Google/LLM en sandbox, sin host Docker socket, sin privilegios root, sin acceso a Redis de producción desde APK no confiables.
- Proteger de scraping enumeración de usernames, hijacking de sesión, replay de ID tokens, token de compra robado, múltiples sesiones, doble gasto, refund fraud y abuso de enlaces.
- Política de privacidad y términos deben describir identidad Google, APK, evidencias, IA externa opcional, analistas humanos, retención, derechos de usuarios y transferencias; consentimiento específico antes de subir.
- Solo admitir APK que el usuario está autorizado a proporcionar y analizar; métodos no aprobados no se anuncian como descifrados y los resultados de terceros requieren revisión de derechos/licencias.
- Auditoría de accesos/reembolsos con retención proporcional y separación de datos fiscales; cumplir solicitudes de acceso/eliminación y obligaciones de conservación legal.

## 8. Pendientes comerciales y de cuenta antes de activar

- Nombre final y política de cambio del handle (longitud, cadencia y nombres reservados); foto de perfil/alias elegibles.
- Configuración y verificación de OAuth Branding y firmas reales, dominios de Google y credenciales servidor.
- Precio real local Play, elegibilidad de suscripción, condiciones para modo B, paquete de créditos, reintentos/resultados parciales y cancelación.
- Responsable legal de venta/facturación y tratamiento fiscal por jurisdicción; no prometer CFDI sin proceso validado.
- Condiciones públicas de reintegro de créditos, reembolso monetario, fraude y reclamación.
- Duración de retención de APK/evidencias/resultados y eliminación de copias offline; límites de descarga/upload.
- Política para colaboración humana: roles, NDA/confidencialidad, equipos aislados y consentimiento a IA externa.
- Qué parte de evidencia técnica se permite descargar al usuario; la admin y la comercial no tienen por qué ser idénticas.

## 9. Referencias oficiales consultadas, sujetas a revisión antes de publicación

- Android Credential Manager / Sign in with Google: https://developer.android.com/identity/sign-in/credential-manager-siwg-implementation
- Verificación backend de ID tokens y sub: https://developers.google.com/identity/gsi/web/guides/verify-google-id-token
- Branding de Google Authentication: https://developers.google.com/identity/verification/authentication-policy-compliance
- Google Play Billing + backend: https://developer.android.com/google/play/billing
- API de compras y estados: https://developers.google.com/android-publisher/api-ref/rest/v3/purchases.products
- Reembolsos oficiales: https://support.google.com/googleplay/android-developer/answer/2741495
- Voided Purchases y conciliación: https://developers.google.com/android-publisher/voided-purchases
- Política de eliminación de cuentas: https://support.google.com/googleplay/android-developer/answer/13327111

**Importante:** estas referencias describen capacidades/políticas de las plataformas, no sustituyen revisión jurídica/contable. Una vez se implemente, la política comercial publicada debe ser acorde al país y a la fecha real de publicación.
