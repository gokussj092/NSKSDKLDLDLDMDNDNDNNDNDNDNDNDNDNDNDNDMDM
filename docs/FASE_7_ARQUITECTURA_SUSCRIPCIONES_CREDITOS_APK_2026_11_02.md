# SP-DECODE — Fase 7: arquitectura de suscripciones, créditos y análisis de APK

**Fecha:** 2026-11-02  
**Rama:** `fix/http-jireh-current-method`  
**Objetivo de versión:** 1.1.26 / build 41 (no modifica Gradle).  
**Estado:** **diseño técnico documentado; sin cobros, suscripciones, saldo, compra ni análisis real habilitados.**  
**Origen:** `PLAN_ANDROID_1_1_26_BUILD_41_2026_11_02.md` y `ADMIN_COMPATIBILIDAD_Y_SOLICITUDES_2026_11_02.md`, además del diseño AMOLED aprobado en fase 6.  
**Separación obligatoria:** no afecta el descifrado actual, exportación JSON/unlocked, catálogo Server VPN, API V1, API V2 existente, ni `feat/version-offline-apk`.

## 1. Contrato de producto: confirmado frente a pendiente

| Regla | Estado | Interpretación |
| --- | --- | --- |
| Acceso al futuro análisis de APK | Confirmado: requiere suscripción | No equivale a «suscripción que incluye análisis ilimitados». |
| Precio de referencia por crédito | Confirmado como intención: **USD 4 por 1 crédito** | Es precio propuesto de 1 crédito, NO cuota de suscripción ni precio universal mostrado en todas las monedas. |
| Coste de un análisis | Confirmado: **1 crédito por APK** | La operación facturable es un trabajo de análisis aceptado y ejecutado satisfactoriamente. No se cobra simplemente al seleccionar un archivo. |
| Pantalla «Próximamente» en 1.1.26 | Confirmado | Sin importación real, pago, saldo falso, balance inicial inventado ni cobro. |
| Suscripción: precio, duración y planes | **Pendiente de decisión comercial** | No crear planes con precios inventados ni renovaciones automáticas sin aprobación. |
| Créditos incluidos con la suscripción | **Pendiente** | No asumir créditos gratis ni recargas mensuales. |
| Vencimiento o transferibilidad de créditos | **Pendiente** | No implementar vencimiento silencioso o transferencias sin reglas y aviso explícitos. |
| Uso de créditos tras cancelar la suscripción | **Pendiente** | Propuesta: conservar saldo comprado, suspender acceso al módulo hasta renovar la suscripción, sin eliminar créditos. Requiere aprobación. |
| Fallo técnico del análisis | **Propuesta conservadora:** no descontar | Reservar durante ejecución, confirmar al generar reporte útil; liberar reserva ante fallo técnico. |
| Resultado parcial, APK repetida, cancelación tardía | **Pendiente** | La propuesta técnica de abajo define estados seguros, pero no convierte estos casos en una decisión comercial aprobada. |
| Integración nueva por sugerencia | Confirmado: gratuita | `Ajustes → Errores y sugerencias` de las fases 4/5 no consume créditos ni requiere el motor de análisis de pago. |

La fase 7 solo entrega arquitectura. Las decisiones pendientes anteriores **bloquean la activación comercial**, no la documentación ni el lanzamiento de la pantalla informativa en 1.1.26.

## 2. Experiencia Android futura (tema AMOLED y 14 idiomas)

- `Aplicaciones / Análisis de APK` continúa en «Próximamente» en 1.1.26. No desplegar botones activos de comprar/analizar, ni simular disponibilidad.
- En una versión posterior, al habilitar el servicio, mostrar claramente: estado de suscripción, créditos **confirmados por servidor**, coste de 1 crédito por análisis, condiciones de devolución, privacidad y confirmación explícita antes de usar saldo.
- Precio mostrado desde Google Play Billing (product details/offer) en la moneda y condiciones locales que devuelva la tienda; **no mostrar USD 4 como precio universal cobrado** cuando Play ofrezca otro importe o moneda. La referencia comercial de USD 4 no sustituye la configuración de Play Console ni reglas fiscales.
- La compra de créditos y la suscripción se muestran como **dos productos distintos**: un producto consumible y una suscripción. La cancelación o suspensión del plan no debe borrarle silenciosamente el saldo a nadie.
- Recuperación de compras/historial y asistencia por disputa deben ser parte del diseño de lanzamiento. No tratar una reinstalación como creación de una identidad nueva con saldo cero si existen créditos comprados.
- Preservar coherencia con Ajustes y pantalla Acerca de fase 6: negro AMOLED, gris para descripción, contraste accesible, navegación Atrás, estados de carga y errores, textos para los 14 idiomas, RTL y dispositivos compactos.
- Un archivo se elige mediante selector de documentos con consentimiento explícito. **Importar no instala, ejecuta ni inicia automáticamente la APK**. No enviar bytes antes de aceptar el aviso de privacidad y confirmar el análisis.

### Puertas de disponibilidad

Definir flags **independientes** en el servidor, todos desactivados de inicio:
- `apk_analysis_available=false`: impide crear trabajos y transferir APK.
- `apk_billing_enabled=false`: impide iniciar compras y canjes; no basta ocultar controles.
- `apk_subscriptions_enabled=false`: no ofrece contratación.
- `apk_analysis_kill_switch=true`: bloqueo operativo con prioridad máxima; no afecta descifrado normal ni las fases 1–6.

La API siempre verifica la puerta, la versión/identidad admitida, la suscripción y el saldo; no confiar en controles Compose o banderas del cliente. No hay que añadir ahora ningún flag de producción.

## 3. Canal de pago y obligaciones de distribución

Para la APK distribuida por **Google Play**, los créditos que dan acceso a una función digital y las suscripciones de acceso al servicio pertenecen a las compras integradas. Diseñar con **Google Play Billing**, salvo que una excepción o programa autorizado aplicable permita otra solución y se evalúe explícitamente. No enlazar a PayPal/Binance/checkout externo dentro del flujo de compra de Play sin esa comprobación. Los iconos de donaciones existentes no son el mecanismo de créditos.

Modelo de productos futuro (identificadores ilustrativos, NO creados):
- `spdecode_apk_credit_1`: producto de compra única **consumible**, entrega 1 crédito tras compra verificada.
- `spdecode_apk_access`: suscripción para habilitar el módulo; base plan, tarifa, período, pruebas, países y ofertas **por definir en Play Console**.
- No crear paquetes promocionales ni planes anuales solo por existir soporte técnico a múltiples productos.

**Ciclo de compra:** Android inicia Billing; envía al backend el `purchaseToken` y el producto anunciado en un canal autenticado; el backend consulta Google Play Developer API, verifica aplicación/producto, estado `PURCHASED`, propiedad/identidad, unicidad y revocaciones; concede el derecho **una sola vez** en la misma transacción de contabilidad; después reconoce/consume el producto según su tipo. Compras `PENDING` no acreditan créditos ni habilitan acceso. Evitar depender únicamente del orden de llegada de callbacks del cliente.

**Fuentes de conciliación:** Real-time Developer Notifications (RTDN), consultas a Play Developer API y Voided Purchases API. RTDN se usa como disparador de reconciliación y se valida antes de modificar derechos. Procesamiento idempotente por `purchaseToken` y `messageId`. Refund/chargeback/revocación crea un ajuste compensatorio auditable y revisa el derecho; nunca borra transacciones históricas. Los créditos ya gastados no se vuelven a gastar al aplicar un reembolso; el tratamiento de saldo insuficiente o deuda queda sujeto a política previamente publicada.

**Suscripción:** estados internos separados de los de crédito (sin mezclar «pagó» con «tiene 1 crédito»). Confirmar estado y `expiryTime` con Play; una cancelación voluntaria habitualmente permite acceso hasta finalizar el período pagado; una expiración confirmada suspende acceso futuro y una revocación puede terminarlo antes. Admisión de períodos de gracia/account hold queda pendiente de producto y se implementará conforme a los estados de Play.

**Plazos y consistencia:** reconocer una compra válida rápidamente; las compras ordinarias que requieren reconocimiento no deben permanecer sin reconocer durante el plazo fijado por Play (habitualmente tres días). Si no puede verificarse/entregarse el beneficio, no marcarla como entregada: realizar reconciliación y, si procede, reembolso/revocación con API oficial. El servidor es la autoridad del derecho, no una `SharedPreference` Android.

Documentación de referencia oficial (verificar de nuevo antes de implementar):
- https://support.google.com/googleplay/android-developer/answer/9858738
- https://developer.android.com/google/play/billing/security
- https://developer.android.com/google/play/billing/lifecycle/one-time
- https://developer.android.com/google/play/billing/lifecycle/subscriptions
- https://developer.android.com/google/play/billing/backend
- https://developer.android.com/google/play/billing/manage-purchases

Las APK distribuidas **fuera de Google Play** necesitarán una decisión independiente de identidad y de canal de pago antes de ofrecer compras. No mezclar tokens ni conceder créditos Play a instalaciones no autorizadas sin un mecanismo verificable de vinculación. No activarlo por defecto.

## 4. Componentes y límites de confianza

`Android Compose → HPKE V2 existente → API de orquestación autenticada → servicio de derechos/billing → base transaccional / ledger → cola de análisis aislado → almacén temporal cifrado de APK y reportes`.

- **Android**: visualización, selector SAF, confirmación, Play Billing y descarga de informes autorizados. Ninguna fuente local crea saldo.
- **API V2**: conservar las protecciones aplicables de sesión, firma PoP, anti-replay, Play Integrity/atestación y RASP según políticas ya existentes. Definir futuros códigos de operación exclusivos en registro central; **no reutilizar la operación 18** destinada a sugerencias/errores. No crear una ruta anónima que eluda V2.
- **Servicio de derechos**: identidad estable con mecanismo de recuperación, verificación de compras, emisión de saldo autoritativo, cupos y acceso por suscripción. Separación entre identidad comercial y claves efímeras de la sesión; rotar clave de dispositivo no debe perder derechos.
- **Base de contabilidad transaccional**: recomendado PostgreSQL u otro almacenamiento ACID con transacciones, restricciones únicas y registros duraderos; **no usar Redis de feedback con TTL 90 días** como fuente financiera de verdad. Redis puede gestionar rate limit o cola, no el saldo definitivo. Esta base aún no existe como parte de esta fase.
- **Trabajador de análisis**: servicio *separado* del descifrador actual y del catálogo; procesamiento estático en entorno sin privilegios, con recursos limitados. No instalar ni ejecutar código de terceros, scripts embebidos o librerías de una APK.
- **Panel administrativo**: módulo futuro de suscripciones, operaciones, reportes y ajustes compensatorios; protegidos con sesión admin, CSRF, auditoría y autorización por rol. **No mezclar** con `/admin/requests` de fase 5, que recibe sugerencias gratuitas.
- **Control de acceso a informes**: comprobar dueño de trabajo en cada consulta; URL temporales firmadas no son credenciales permanentes; no indexar informes en el catálogo.

### Identidad comercial y recuperación

Decisión abierta: cuenta SP-DECODE recuperable, vinculación aprobada a una cuenta autenticada, o un método equivalente. Solo atestación de dispositivo/keystore sin recuperación **no es suficiente** para proteger saldo adquirido ante pérdida, reinstalación o cambio de móvil. No guardar credenciales de Google, tarjetas ni tokens privados del usuario en la app. El `purchaseToken` debe guardarse protegido en backend con control de acceso estricto; en logs, usar un identificador derivado, no el token íntegro.

## 5. Modelo lógico sugerido (no migraciones ni tablas creadas)

| Entidad | Campos mínimos y restricciones |
| --- | --- |
| `commercial_account` | `account_id` UUID, identidad de recuperación, estado, creado; controles de acceso y borrado conforme a obligaciones aplicables. |
| `purchase` | `purchase_id`, `account_id`, `provider=google_play`, `product_id`, `purchase_token_hash` (único), referencia cifrada de token cuando sea necesaria para conciliar, `status`, fechas, tipo, moneda/importe informativos verificados; nunca confiar en el precio del cliente. |
| `subscription_entitlement` | `account_id`, producto/plan, estado verificado, `expires_at`, `last_verified_at`, referencia a compra/encadenamiento. |
| `credit_ledger` | `entry_id`, `account_id`, `amount` entero con signo, `reason` (compra, consumo, restitución, ajuste, revocación), `purchase_id/job_id`, `idempotency_key` única, `created_at`; **append-only**. |
| `credit_reservation` | `reservation_id`, `account_id`, `job_id` único, `amount=1`, `status`, `expires_at`; idempotente y bloqueado por transacción. |
| `analysis_job` | `job_id`, `account_id`, `client_request_id` único por cuenta, SHA-256 de APK, estado, versión de analizador, categoría de resultado, marca de consumo/entrega, tiempos. |
| `analysis_artifact` | `job_id`, metadatos estrictos, ubicación cifrada temporal, caducidad, versión de esquema, política de descarga. |
| `billing_event_inbox` | identificador fuente único, tipo, hora, estado de conciliación, hash de evento, contador de reintentos seguro. |
| `admin_audit_log` | actor, acción, objeto, valor anterior/nuevo, motivo, sello temporal; sin secretos ni APK. |

**Invariantes transaccionales:**
1. `saldo_disponible = suma(credit_ledger.amount) - suma(reservas_activas.amount)`, sin saldo negativo por carreras concurrentes. Un saldo materializado opcional se actualiza en la misma transacción.
2. Solo una acreditación por compra verificada; `UNIQUE(provider, purchase_token_hash)` y `UNIQUE(credit_ledger.idempotency_key)`.
3. Una misma solicitud idempotente devuelve el mismo trabajo y jamás consume de nuevo. Repetir el **mismo APK con nueva orden** es un caso de producto pendiente, no automáticamente gratis ni doble cobro.
4. Cada trabajo consume **como máximo 1 crédito**, aun con reintentos del worker, error de red, doble pulsación o ejecución concurrente.
5. La cuenta que creó un trabajo es la única autorizada a ver su estado y su informe.
6. Ajustes de operador **compensan** asientos, no editan/borran el ledger; cada ajuste requiere motivo y auditoría.
7. Un fallo de verificación de Play nunca concede créditos, aunque el cliente afirme «compra correcta».

## 6. Flujo de un trabajo y política de crédito sugerida

`Seleccionar APK → consentimiento → prevalidación sin cobro → confirmar 1 crédito → verificar suscripción y saldo en backend → reservar crédito atómicamente → cargar/analizar → informe útil validado → confirmar consumo (ledger -1) → entregar reporte`.

La prevalidación debe comprobar tamaño/formato/ZIP, cabeceras y estructura mínima, cupo, disponibilidad, suscripción y límites del servicio antes de confirmar. La reserva no es un descuento definitivo y debe vencer o poder reconciliarse. No publicar el informe si se ha perdido el vínculo con el trabajo/usuario.

| Evento | Estado del trabajo | Impacto sugerido en crédito |
| --- | --- | --- |
| APK inválida detectada en prevalidación | `rejected` | 0 reservado; 0 consumido |
| Trabajo aceptado | `queued` | Reserva 1 (saldo disponible baja; saldo contable no) |
| Analizador en curso | `running` | Reserva retenida dentro del plazo seguro |
| Reporte útil completo y persistido | `completed` | Confirmar 1 cargo en ledger y liberar reserva atómicamente |
| Error técnico, worker caído, timeout definitivo | `failed` | Liberar reserva; 0 consumido |
| Cancelación antes de iniciar cómputo | `cancelled` | Liberar reserva; 0 consumido |
| Cancelación durante cómputo | `cancelling` | Reglas económicas pendientes; propuesta: no cargar sin informe útil entregable |
| Reporte parcial | `partial` | **No cobro automático hasta decidir** qué constituye informe útil; propuesta por defecto: liberar crédito |
| Reintento del mismo `client_request_id` | estado existente | No nueva reserva ni nuevo cargo |

La caducidad de reserva se define con reconciliación y estado real del worker: no debe liberar y volver a gastar una reserva mientras el job sigue activo sin mecanismo de exclusión. Cobrar después de entregar y almacenar un informe recuperable evita perder el resultado cuando cae la conexión del móvil.

**Diferenciar restituciones:** devolver un crédito porque un trabajo falló ≠ reembolsar una compra monetaria. Reembolso de Play se procesa por los canales oficiales y puede requerir retirar derechos no gastados; si el usuario ya usó créditos, la resolución requiere una política publicada y revisión de abuso, nunca eliminar un saldo sin registrar motivo.

## 7. Contrato propuesto de API futura (sin rutas ni operaciones desplegadas)

Todos los mensajes Android de esta sección son **conceptuales** y deberán mapearse a operaciones nuevas y exclusivas del **transporte HPKE V2** ya existente; no sobrecargar operación 18, no abrir un endpoint de compra accesible sin autorización.

| Operación lógica | Entradas mínimas | Respuesta |
| --- | --- | --- |
| `GET commercial-state` | sesión/identidad | feature flags, derecho de suscripción, saldo disponible/reservado, versiones del contrato; sin tokens |
| `POST verify-purchase` | producto, `purchaseToken`, idempotencia | estado verificado de compra, delta aplicado una vez; nunca confiar en importe aportado por Android |
| `POST analysis/preflight` | metadatos mínimos, tamaño/hash, versión | elegibilidad, límites, política de privacidad y coste de 1 crédito; no ejecutar APK |
| `POST analysis/jobs` | `client_request_id`, confirmación explícita, preflight autorizado | `job_id`, reserva y estado |
| `PUT analysis/blob` | transferencia autorizada vinculada a `job_id` | acuse por fragmento y límite de bytes; no mezclar blobs con catálogo HPKE |
| `GET analysis/jobs/{id}` | identidad autenticada | estado, error tipificado, disponibilidad de informe |
| `POST analysis/jobs/{id}/cancel` | identidad y motivo | resultado de cancelación e impacto de reserva |
| `GET analysis/jobs/{id}/report` | identidad del propietario | informe descargable autorizado; sin revelar datos a otras cuentas |
| `POST purchases/restore` | identidad recuperada y compras consultadas | conciliación; **nunca** recrear créditos por tokens ya consumidos |

**Seguridad de API:** antifraude por cuenta/dispositivo; tamaño máximo del cuerpo y de APK; cuotas diarias, concurrencia y rate limits configurables; controles contra replay y cross-account; auditoría; no almacenar archivos en logs, métricas, backups de Redis ni colas que también procesen VPN. El panel debe informar errores agregados sin exponer bytes, claves o informes privados.

## 8. Motor de análisis de APK: frontera de privacidad y seguridad

Servicio **de investigación técnica**, no promesa de producir automáticamente un descifrador funcional. Primordialmente **análisis estático** de artefactos proporcionados voluntariamente.

- Extraer de forma segura: hash SHA-256, metadatos de paquete/versión, manifiesto, permisos, certificados públicos, estructura del contenedor, nombres de recursos/assets, bibliotecas y referencias técnicas con procedencia; etiquetar hipótesis separadas de hallazgos verificados.
- Detectar archivos comprimidos anidados, zip bombs, traversal/symlinks, tamaños malformados, APK truncadas y tipos inesperados; imponer tamaño de APK, memoria, CPU, tiempo, profundidad y bytes extraídos. **Los límites definitivos son pendientes de pruebas**, no cifras inventadas.
- Ejecutar como usuario sin privilegios en contenedor/VM aislado, filesystem temporal, red bloqueada por defecto, sin volúmenes de secretos del VPS, sin acceso a claves HPKE, Redis interno, base de pagos, host Docker, catálogo o API de administración. Solo salidas declaradas; jamás ejecutar el DEX/native de la APK.
- Si aparecen tokens, contraseñas, endpoints internos o contenido personal dentro de la muestra, **no publicar automáticamente** esos valores íntegros; redactar secretos en vistas, logs e informes por defecto y controlar quién puede exportar una versión más técnica.
- Limitar retención del APK crudo y del reporte; cifrado en reposo y borrado programado verificable. **Plazos concretos pendientes** de privacidad, soporte y costes. Permitir consulta del estado de eliminación y documentar excepciones legales.
- Solo analizar material sobre el cual el usuario tenga autorización o derecho de investigación; aclarar restricciones de propiedad intelectual, protección de datos y condiciones de servicios aplicables.

**Resultado:** informe técnico + estructura con campos de origen, certeza y límites, nunca garantía de script listo, método vigente o catálogo descifrado.

## 9. Estados y fallos que debe comunicar Android

- `coming_soon`: sin saldo visible ni acciones de compra/archivo.
- `subscription_required`, `subscription_pending`, `subscription_active`, `subscription_expired`, `subscription_revoked`.
- `purchase_pending`, `purchase_verified`, `purchase_failed`, `purchase_refunded`; no acreditar en PENDING.
- `credits_insufficient`, `credit_reserved`, `credit_consumed`, `credit_released`, `reconciliation_pending`.
- `job_queued`, `job_running`, `job_completed`, `job_partial`, `job_failed`, `job_cancelled`.
- `service_unavailable` y `privacy_consent_required`.

Traducir los nuevos textos a los 14 idiomas **cuando se implemente el módulo**, no añadir cadenas de pantalla activa ni permisos innecesarios en 1.1.26. Todas las vistas deben distinguir incertidumbre de fracaso; «pago recibido» no significa «crédito acreditado» hasta verificación final del backend.

## 10. Pruebas y puertas de lanzamiento posterior

**Facturación:** compra válida, pendiente, cancelada, repetida, token de otro producto/paquete/cuenta, consumo reintentado, reinicio tras conceder crédito pero antes de responder, RTDN duplicada/fuera de orden, revocación, contracargo, recuperación tras cambio de dispositivo, expiración y cancelación de suscripción, precios localizados.

**Ledger:** 100+ solicitudes concurrentes con 1 crédito, doble pulsación, cola duplicada, caída de DB/worker y reanudación; comprobar `saldo≥0` y que una compra no se entrega dos veces, un job no se cobra dos veces, errores no cobran y reservas huérfanas se liberan sin carrera.

**Analizador:** APK benignas, corruptas, renombradas, enormes, zip bomb, traversal, payload malicioso, anidamientos, bibliotecas nativas, manifests malformados; no ejecución accidental, sin red/salida de secretos, límites de recursos y eliminación. Informe recuperable por dueño tras desconexión; acceso ajeno denegado.

**Integración:** HPKE V2, admisión Play, PoP, anti-replay, políticas temporales y RASP; compatibilidad 14 idiomas/RTL; catálogos V1/V2 independientes; descifradores/exportadores offline/cloud sin regresiones; no nuevas consultas por abrir Ajustes o «Próximamente».

**Gates para activar:** decisiones comerciales aprobadas por el propietario; Play Console configurada y términos publicados; backend y base transaccional operativos; recuperación de identidad; pruebas de compras de licencia, refunds y notificaciones; privacidad/retención y límites de APK revisados; auditoría del panel; pruebas físicas y CI; kill switch verificado; release autorizado. Si falla cualquier gate, mantener compras y análisis desactivados.

## 11. Decisiones concretas que faltan al propietario

1. **Suscripción:** precio, periodicidad, cobertura por países, prueba gratis, créditos incluidos y límites de uso.
2. **Créditos:** si caducan, si hay paquetes/descuentos, y qué ocurre con créditos comprados tras expirar la suscripción.
3. **Cobro por trabajo:** definir «reporte útil» y decidir si un reporte parcial consume 1 crédito; cancelación a mitad de análisis; repetición de APK con nuevo pedido.
4. **Identidad y recuperación:** cuenta comercial recuperable y vínculo con instalaciones Telegram/Play.
5. **Privacidad:** consentimiento, máximo de APK, tiempo de retención de APK/informes, eliminación, soporte y jurisdicciones.
6. **Facturación/reembolsos:** operativa Play, tratamiento de créditos consumidos en compras posteriormente revocadas, política de asistencia y prevención de fraude.

Hasta su resolución, cualquier diseño técnico de estos puntos es una **recomendación**, no una instrucción para cobrar.

## 12. Entregables de esta fase y continuidad

- **Entregado en fase 7:** esta especificación de arquitectura, modelo de contabilidad, límites de confianza, ciclo de compra/análisis, reconciliación, casos de error y matriz de QA.
- **No entregado:** código Kotlin/C++, servicios de pago, suscripciones en Play Console, tablas SQL, endpoint nuevo, panel comercial, trabajos de análisis, almacenamiento de APK, APK/AAB compilados.
- **Fase 8:** probar y preparar la versión 1.1.26 de las funciones 1–6. La fase 7 **no debe bloquear el release** por no estar activado su sistema comercial. No subir versionName/versionCode ni lanzar GitHub Actions por esta documentación.
- **Posteriormente:** aprobar producto y condiciones; diseñar identidad; implementar backend transaccional aislado; integrar Billing; implementar worker estático seguro; pruebas de compras y fallos; activar progresivamente con kill switch. Mantener `main` y `feat/version-offline-apk` intactas.
