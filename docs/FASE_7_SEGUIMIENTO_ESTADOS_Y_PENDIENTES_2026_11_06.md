# SP-DECODE — Fase 7: estado, pendientes y punto de reanudación

**Actualizado:** 2026-11-06.  
**Rama:** `feat/nuevas-integraciones`. **Commit auditado:** `6deb4d5329b3a9526d49fe5e02f48b7a0ccef6a8`.  
**Ámbito:** subfases **F7-A0 a F7-A9** de la futura función de análisis de APK en Cloud. **No confundir** con las fases previas de la aplicación Android 1.1.26.

**Convención:** IMPLEMENTADO significa archivos operativos identificados; VALIDADO requiere pruebas reales con identificador de ejecución; PARCIAL significa que hay entregables, pero no todos los criterios de salida; DOCUMENTADO/PENDIENTE significa que existe diseño, **no** el sistema funcional. El método histórico VERIFIED no implica APPROVED para ejecución automática.

## 1. Estado de todas las etapas

| Subfase | Estado | Implementado / evidencia disponible | Pendiente para poder terminarla |
|---|---|---|---|
| **F7-A0** Inventario y política de evidencias | **PARCIAL; CI específico VERDE** | Inventario **63 scripts**, **7 paquetes Python fijados**, **11 dossiers** de app/build; validador, tests y workflow. | Revisar licencias/transitivas/ABI/hash, aprobar herramientas individualmente, esquemas de reportes/checkpoints, corpus APK/APKS autorizado, ampliar CI y protección de rama. |
| **F7-A1** Google Cloud y acceso Google | **DOCUMENTADO / NO IMPLEMENTADO** | Requisitos Google-only y arquitectura definidos. | Clientes OAuth Android/Web, backend de tokens/sesiones, Credential Manager, configuración real Google Cloud/Play y pruebas de seguridad. |
| **F7-A2** Perfil, handle y privacidad | **DOCUMENTADO / NO IMPLEMENTADO** | Diseño y campos de Mi cuenta. | DB/migraciones, handle único, consentimiento/borrado, UI real y pruebas de concurrencia/privacidad. |
| **F7-A3** Créditos y ledger | **DOCUMENTADO / NO IMPLEMENTADO** | Regla de reservar/cobrar al entregar/liberar en fallo. | Ledger ACID, idempotencia, reservas/expiración, ajustes auditados, 100 solicitudes concurrentes y pruebas de fallo. |
| **F7-A4** Upload y almacenamiento APK | **DOCUMENTADO / NO IMPLEMENTADO** | Protocolo deseado de chunks, SHA-256, consentimiento. | Subida resumible, almacenamiento cifrado/TTL/cuotas, prevención ZIP bomb/traversal, permisos por cuenta. |
| **F7-A5** Worker y análisis automático | **DOCUMENTADO / NO IMPLEMENTADO** | Scripts de investigación preexistentes y diseño del worker; no equivalen al nuevo servicio. | Orquestador, worker estático aislado, allowlist de herramientas, reporte modo A, checkpoints y test adversarial. |
| **F7-A6** Soporte APK humano | **DOCUMENTADO / NO IMPLEMENTADO** | Flujo de escalado, revisión y entrega especificados. | Bandeja/casos admin, descargas efímeras auditadas, entrega validada, cierre sin cobrar y controles de rol/MFA. |
| **F7-A7** Google Play Billing | **DOCUMENTADO / NO IMPLEMENTADO** | Políticas de verificación servidor y compras descritas. | SKU oficiales, BillingClient, Play Developer API, RTDN, reconciliación y pruebas de compra/reembolso. |
| **F7-A8** Historial y reembolsos | **DOCUMENTADO / NO IMPLEMENTADO** | Reglas para recibos y devolución de crédito vs dinero. | Órdenes, recibos reales, historial, flujos refund de Google y conciliación/fiscalidad. |
| **F7-A9** Integración Android y beta | **DOCUMENTADO / NO IMPLEMENTADO** | UI anterior «Próximamente» y propuestas AMOLED/localización; no acredita servicio APK funcional. | Pantallas y APIs reales, 14 idiomas, accesibilidad, pruebas Play e2e, privacidad, rollback y rollout progresivo. |

**Resumen:** F7-A0 es la única subfase en ejecución. **Ninguna F7-A1…F7-A9 se declara completada.** Los módulos Android/Cloud previos se mantienen separados de estas nuevas subfases.

## 2. F7-A0: trabajos integrados y verificados

| ID | Trabajo realizado | Ruta/evidencia | Estado |
|---|---|---|---|
| A0-I01 | Congelar referencia de fuentes de herramientas sin editarlas | `analysis/platform/apk-tooling/tool_sources.v1.json` | 63 scripts Python/JS, UNREVIEWED para automatización |
| A0-I02 | Registro de dependencias directas | `analysis/platform/apk-tooling/dependencies.v1.json` | 7 PyPI fijadas; licencias/hashes externos por revisar |
| A0-I03 | Inspección estructural de expedientes | `scripts/ci/check_method_evidence.py` | 11 dossiers app/build con estructura básica; NO comprueba métodos remotos reales |
| A0-I04 | Gate de cambios (fuentes, proveedores y evidencia) | `scripts/ci/check_method_evidence.py` | Validado en pull request |
| A0-I05 | Test suite con fixtures sintéticos offline | `tests/test_method_evidence_a0.py` | **11/11 OK** en GitHub Actions |
| A0-I06 | Workflow independiente | `.github/workflows/f7-a0-method-evidence.yml` | **SUCCESS** en run 42303343370, intento 2 |
| A0-I07 | Documento técnico de alcance | `docs/FASE_7_A0_INVENTARIO_Y_GATE_2026_11_06.md` | Existe; vinculado a este tracker |

**Prueba real:** [F7-A0 Method Evidence, intento 2, SUCCESS](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42303343370). Logs de job: `Ran 11 tests ... OK`; `F7-A0: tools=63 pinned-deps=7 app-dossiers=11 structurally-complete=11`. Los pasos de pruebas, inventario y gate de PR aprobaron.

**No se modificó el código de `scripts/apk_analysis/` ni los métodos `decoders/Python/apps/` para F7-A0.** Su código operativo no se reemplaza ni se «optimiza» de manera unilateral.

## 3. F7-A0: pendientes explícitos antes de cerrar

| ID | Pendiente | Evidencia necesaria / criterio de cierre |
|---|---|---|
| **A0-P01** | Auditoría de origen, licencias, versiones y dependencias directas/transitivas | Licencia validada por herramienta, versión efectiva, SHA-256 verdadero del artefacto distribuido, ABI/OS y origen confiable; no inventar valores. |
| **A0-P02** | Matriz de herramientas → consumidores → capacidades | Mapear cada script a apps/build, invocación, tipo de evidencia, uso de red, permisos y pruebas existentes, con hashes de archivo/commit. |
| **A0-P03** | Aprobación de ejecución automática individual | Cada herramienta candidata documenta sandbox, comandos permitidos, recursos/timeout y revisiones; lo pendiente sigue UNREVIEWED. |
| **A0-P04** | Esquemas versionados de resultado y checkpoint | Contratos con estado/certeza, hash, errores, privacy labels, provenance, outputs parciales y tests de validación. |
| **A0-P05** | Corpus autorizado de APK/APKS y tests de límites | ZIP corrupto/bomb/traversal, DEX múltiple, ELF malformado, límites de tiempo/memoria/disco. No ejecutar APK de terceros en producción. |
| **A0-P06** | Ampliar cobertura del gate y legado | Rutas Cloud/worker/plugins, hashes y dependencias de todos los afectados; baseline gradual y excepciones justificadas. |
| **A0-P07** | Validación CI y protección opcional de rama | Auditor de checks y tests en CI. Por decisión expresa del propietario, **NO** activar Branch Protection ahora; revisión manual antes de merge. Sin atribuir bloqueo de GitHub inexistente. |
| **A0-P08** | Regresión real sin tocar scripts funcionales | Pruebas independientes por formatos/consumidores afectados, sin declarar VERIFIED_REAL por fixtures sintéticas. |
| **A0-P09** | Aceptación formal de salida | Resolver P01–P08 o documentar expresamente limitaciones y decisiones de riesgo; no marcar A0 DONE anticipadamente. |

## 4. Qué falta exactamente en las etapas F7-A1…A9

### F7-A1 — Google Sign-In
**Hecho:** especificación Google-only, sin login por correo/contraseña obligatorio y sin bloquear funciones gratuitas.  
**Falta:** branding y OAuth Cloud real (Android/Web/Play signing), Google Identity/Credential Manager en cliente, backend que valide `aud/iss/exp/sub/nonce`, sesiones, revocación y separación de roles. **Gate:** tokens incorrectos/caducados/replay rechazados y sesión recuperable en pruebas. **Depende de:** preparación externa Google Cloud.

### F7-A2 — Perfil, handle, privacidad
**Hecho:** diseño del perfil con nombre visible, @handle y correo read-only.  
**Falta:** migraciones SQL, índices únicos, canonicalización de username, consentimiento versionado y eliminación de cuenta/sesiones; UI real. **Gate:** dos solicitudes simultáneas al mismo handle no duplican y la privacidad funciona. **Depende de:** A1.

### F7-A3 — Créditos
**Hecho:** reglas de negocio y ledger definidos en documentos; precio final/suscripción aún necesitan decisiones.  
**Falta:** saldos/ledger persistente ACID, reserva/consumo/liberación idempotentes, recuperación ante crash y concurrencia, ajustes administrativos. **Gate:** sin doble gasto con 100 operaciones y 1 crédito; sin cargo por trabajo fallido. **Depende de:** A1/A2.

### F7-A4 — APK upload
**Hecho:** especificación de transferencia grande segura separada del decodificador Cloud actual.  
**Falta:** sessions/chunks/hash, cuota, almacenamiento cifrado, TTL, consentimiento, tratamiento anti ZIP bomb y autorización por cuenta. **Gate:** parcial nunca analiza, usuario ajeno no lee, cancelación no cobra. **Depende de:** A1/A3.

### F7-A5 — Análisis automático
**Hecho:** recursos de análisis preexistentes e inventario A0; no es aún un worker nuevo.  
**Falta:** AnalysisOrchestrator, StaticApkAnalyzer, EvidenceIndex, ReportStore, sandbox no privilegiado y sin secretos, checkpoints idempotentes, informe técnico A con certeza y límites; pruebas de crash en cada etapa. **Gate:** reproducibilidad y no escape/fuga. **Depende de:** A0/A4.

### F7-A6 — Soporte humano
**Hecho:** modelo administrativo y reglas de entrega/no cobro diseñados.  
**Falta:** bandeja de casos, tickets de descarga temporales/únicos, MFA, auditoría, revisión fuera de producción, carga/entrega verificada y cierre. **Gate:** acceso ajeno denegado, sin doble cargo, sin solución → crédito liberado. **Depende de:** A3/A4/A5.

### F7-A7 — Google Play Billing
**Hecho:** diseño de verificación por backend, no Kotlin como autoridad financiera.  
**Falta:** catálogo y SKUs aprobados, BillingClient, verificación Play, RTDN/PubSub, Voided/chargebacks y conciliación; pruebas Play con testers. **Gate:** PENDING no acredita, compra verificada se acredita una vez, refund se reconcilia. **Depende de:** A1/A3 + Play Console.

### F7-A8 — Historial/recibos
**Hecho:** modelo de movimientos/recibos y distinción de devoluciones especificados.  
**Falta:** UI/APIs de transacciones, recibos informativos y control de fiscalidad, solicitud y administración de refund y conciliación con ledger. **Gate:** importes/monedas verdaderos y nunca refund duplicado. **Depende de:** A2/A3/A7.

### F7-A9 — Android beta y lanzamiento
**Hecho:** placeholder AMOLED previo, «Próximamente», sin simular saldos/compra; **no** da por hecha integración funcional.  
**Falta:** pantallas y transferencia conectadas a backend, estados reales, 14 traducciones, accesibilidad, Play beta, privacidad/seguridad, pruebas end-to-end de fallo, humano, cobro y devolución. Modo B (código IA) solo con revisión/gate propios y precio aprobado. **Gate:** beta firmada con evidencia; rollback sin perder saldos. **Depende de:** A0–A8.

## 5. Incidencia transversal de QA (no atribuida a F7-A0 sin investigación)

- **F7-A0 CI:** SUCCESS, run [42303343370](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42303343370), intento 2.
- **Validate SP-DECODE:** FAILURE, run [42303343453](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42303343453), intento 2. **1,206** tests ejecutados, **13 failures, 3 errors, 9 skipped**. Falla el paso `Run server and Cloud unit tests (no historical Android local decoder parity)`. Se requiere diagnóstico separado: no se ha probado que F7-A0 sea causa ni que los descifradores estén rotos.

**QA-01, errores (3):**
- `test_android_remote_formats.RemoteFormatsAndroidTests.test_abowaged_fallback_survives_stale_remote_format_snapshot`
- `test_cloud_c0_inventory.CloudC0BaselineTests.test_audit_report_contains_no_secrets_or_file_payloads`
- `test_cloud_c0_inventory.CloudC0BaselineTests.test_ui_ux_source_files_have_exact_original_git_blob_ids`

**QA-01, fallos (13):**
- `test_android_catalog_interactions_v120.CatalogInteractions.test_catalog_is_foreground_confirmed_and_remote_routed`
- `test_android_remote_formats.RemoteFormatsAndroidTests.test_cached_snapshot_is_versioned_and_fail_closed`
- `test_android_remote_formats.RemoteFormatsAndroidTests.test_cloud_generated_ui_uses_dynamic_snapshot_during_import`
- `test_android_server_vpn_update_opt_in.ServerVpnUpdateOptInContracts.test_manual_probe_prompts_before_download_and_header_only_button`
- `test_cloud_c0_inventory.CloudC0BaselineTests.test_cli_check_with_no_decoder_execution`
- `test_cloud_c4_android_bridge.CloudC4Tests.test_original_ui_sources_exactly_match_c0`
- `test_cloud_c8_android_input_routes.CloudC8ClientRouting.test_cloud_text_vendor_prefixes_are_explicit_and_keep_content`
- `test_cloud_c8_android_server_vpn.PhaseVServerVpnIntegration.test_aes_gcm_no_backup_integrity_and_manual_catalog_retry`
- `test_cloud_history_actions.CloudHistoryActionsTest.test_export_is_user_selected_json_and_never_eager_parses_nur`
- `test_compatible_export_integration.CompatibleExportIntegration.test_release_metadata_and_workflow_artifacts_agree`
- `test_global_cloud_ui_contract.GlobalCloudUiContracts.test_frozen_c0_ui_remains_bit_for_bit_unchanged`
- `test_r0_r8_npvs_contract.R0R8NpvsContracts.test_r8_keeps_exact_registered_jni_and_keystore_bridge`
- `test_server_vpn_icon_policy.ServerVpnIconPolicyTests.test_client_preserves_integrity_original_cache_and_general_transport_budget`

**QA-01 próximo paso:** comparar contratos antiguos con intención y comportamiento actual; distinguir aserciones obsoletas de regresiones auténticas antes de modificar algo. No silenciar tests ni cambiar hashes congelados sin prueba/autorización. Registrar resultado separado de F7 y repetir validación general antes de merge.

## 6. Orden de continuación y handoff al siguiente chat

1. **QA-01:** analizar los 16 incidentes con logs y revisión de contratos actuales; preservar scripts de análisis y descifradores funcionales.
2. **F7-A0-P01/P02/P03:** orígenes, licencias, dependencias transitivas, clasificación por capacidad y decisión de herramientas aptas (sin activar automáticamente).
3. **F7-A0-P04/P05/P06:** contratos de checkpoint/report, corpus autorizado y cobertura CI extendida.
4. **F7-A0-P07/P08/P09:** required checks, regresión y aprobación de cierre; no dar A0 DONE sin evidencia.
5. **F7-A1** Google-only y sucesivas A2…A9 según el plan maestro.

**Instrucción de reanudación:** «Continúa en `feat/nuevas-integraciones` desde `docs/FASE_7_SEGUIMIENTO_ESTADOS_Y_PENDIENTES_2026_11_06.md`. Verifica HEAD y Actions, atiende QA-01 y F7-A0-P01/P02/P03, registra commits y tests, conserva íntegros los analizadores existentes y cumple `analysis/METHOD_EVIDENCE_POLICY.md`. No despliegues producción ni hagas merge a main sin revisión.»

**Regla de seguimiento:** cada tarea cerrada debe registrar código/commit, pruebas/ejecución y limitaciones; actualizar esta matriz y los pendientes. La documentación no es prueba de endpoint funcional, pago real ni compatibilidad con una APK externa.

## Referencias

- [Plan maestro F7-A0–A9](FASE_7_PLAN_IMPLEMENTACION_Y_QA_2026_11_04.md)
- [F7-A0 inventario y gate](FASE_7_A0_INVENTARIO_Y_GATE_2026_11_06.md)
- [Política de evidencias](../analysis/METHOD_EVIDENCE_POLICY.md)
- [Resultados A/B](FASE_7_APK_AUTOANALISIS_DOS_SALIDAS_PENDING_2026_11_02.md)
- [Google, pagos y soporte humano](FASE_7_CUENTAS_GOOGLE_PAGOS_Y_SOPORTE_APK_2026_11_04.md)

## QA-01 — CI dinámico y contratos de código vigente (2026-11-06)

**Intervención en feat/nuevas-integraciones:** solo infraestructura CI, scripts de auditoría, pruebas y documentación. No modificar descifradores, métodos VPN o flujos Cloud operativos por errores de aserción histórica.

- scripts/ci/current_android_contracts.py: obtiene versionName/versionCode de Gradle, compara dinámicamente registros JNI C++ con declaraciones Kotlin sin cuenta fija y comprueba launchers actuales y restricciones de backup/tráfico no cifrado.
- tests/test_ci_current_android_contracts.py: tests positivos y negativos deliberados para versión, JNI y AndroidManifest.
- Se eliminan hashes UI por versión como barrera activa de C0, pero permanecen los contratos Cloud/seguridad/catálogo y los informes históricos archivados.
- Los tests que antes buscaban llamadas en MainActivity comprueban el router que realmente las implementa y la UI comprueba el cuadro de descarga con progreso de bytes y confirmación.
- validate.yml mantiene la suite integral de Cloud/servidor y añade preflight dinámico. La compilación y las pruebas instrumentadas Android siguen siendo gates independientes.
- workflows de APK/AAB ahora derivan versiones de Gradle; las identidades de firma y controles de distribución no se cambian.
- QA-01 se considerará DONE **solo si el nuevo run de Validate SP-DECODE aprueba**, sin silenciar la suite ni modificar analizadores para satisfacer tests.

**Observación:** el workflow manual play-beta-artifacts.yml mantiene la restricción de repositorio privado ya existente; en una copia pública no se ejecuta. Es una decisión de seguridad separada de los 16 fallos.

### Cierre del mantenimiento sin versiones fijas en workflows

El workflow de firma de la rama se llama `android-branch-signed-release.yml` y obtiene versión y build desde Gradle; no se crea un nuevo workflow por cada versión. La clase Java del test de transporte V2 se genera desde Kotlin; al agregar o retirar un JNI no se actualizan manualmente el total ni las declaraciones del fixture. El test correspondiente valida **paridad dinámica**, no la existencia obligatoria del método de cancelación de una versión concreta.

La suite Validate SP-DECODE aprobó tras eliminar los 13 fallos y 3 errores de origen: runs [42310607488](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42310607488) y [42310909607](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42310909607). Mantener pendiente el gate completo del último commit hasta verificar su ejecución propia, incluida la integración V2 del host JNI generado.

## F7-A0-P01 — Avance 2026-11-06

Estado PARCIAL. Se revisaron las siete dependencias directas con sus fichas y hashes SDIST publicados; 63/63 scripts están intactos. Restan ruedas instaladas, transitivas, mínimo Python 3.11 por Pillow 13 y revisión de licencias de Unicorn/CairoSVG. No se modificaron herramientas funcionales. Detalles: [F7-A0-P01](FASE_7_A0_P01_AUDITORIA_DEPENDENCIAS_2026_11_06.md).


### Validación CI de P01 (GitHub Actions)

[F7-A0 Method Evidence, run 42314608709](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42314608709), resultado **SUCCESS** (commit f263c3587e9cca8d9a87496b95cf9ab7880719b9). Ejecutados 11 tests de evidencia + 6 tests nuevos de metadatos. Inventario: 63 scripts, 7 pins directos, 11 dossiers. Verificador P01: 7 SDIST de referencia, 0 wheels instalados atestiguados y 0 autorizaciones automáticas. Estado P01 **PARCIAL**, pendiente wheel/ABI/transitivas/revisión jurídica. No implica fallo funcional de herramientas anteriores.

## F7-A0-P02 — Inventario dinámico (2026-11-06)

**PARCIAL:** se agregó `scripts/ci/map_apk_tool_usage.py` y pruebas con fixtures `tests/test_a0_tool_usage.py`. El job F7-A0 genera el mapa `f7-a0-usage.json` con hashes, argumentos, imports, señales de riesgo, referencias a apps/build y tests; excluye la propia baseline para no inflar consumidores. **No se tocaron ni ejecutaron los métodos funcionales.** P02 pendiente: usos indirectos, capacidades realmente verificadas y política P03. [Documento de P02](FASE_7_A0_P02_MAPA_HERRAMIENTAS_2026_11_06.md).


### Validación verificada en GitHub Actions

[F7-A0 Method Evidence — run 42316597610](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42316597610) concluyó **SUCCESS** sobre el commit `ca2f699`. Se aprobaron **11 pruebas de evidencia, 6 de dependencias y 7 del nuevo mapa** (24 pruebas en estas tres suites).

El escaneo de P02 informó: **63 herramientas intactas**, 61 Python + 2 JavaScript, **63 mencionadas por al menos un archivo**, **8 con referencias explícitas en expedientes de app/build**, **22 con referencia explícita en pruebas**, 0 errores de parseo y **0 autorizaciones de ejecución automática**.

**La cifra 63 mencionadas no indica 63 herramientas en producción**: las referencias pueden proceder de documentación general. Los grupos de 8 y 22 contabilizan *herramientas con al menos una referencia*, no número de aplicaciones ni pruebas exitosas.

El workflow publicó el artefacto `f7-a0-evidence` (incluye `f7-a0-usage.json`), disponible desde la página de la ejecución durante su período de retención. Este informe es generado automáticamente, no un historial fijo por versión.

**P02 sigue PARCIAL:** faltan análisis de consumidores indirectos y verificación de las capacidades reales por aplicación; estas auditorías no alteran ni certifican los métodos existentes.

## F7-A0-P03 — Entorno separado y recursos persistentes

**EN IMPLEMENTACIÓN (no desplegado):** nuevo `cloud/apk_analysis/` con Dockerfile dedicado, Compose opt-in, volumen `spdecode-apk-tools-cache` para JADX verificado, dependencias instaladas por imagen y no por trabajo, sandbox offline no root y gestor de job temporales. La limpieza **solo** se permite tras confirmación de resultado durable o cierre terminal; conserva trabajos escalados a soporte humano. Las 63 herramientas siguen intactas; `inspect_apk.py` y `decompile.py` son candidatos deshabilitados pendientes de pruebas P05. Requiere host de pruebas más potente que el VPS actual de ~1 GB. [Documentación P03](FASE_7_A0_P03_ENTORNO_PERSISTENTE_2026_11_06.md). Falta A4/A5/A9 para procesamiento automático desde Android y servidor.


### Resultados verificados en GitHub Actions (P03)

La ejecución [F7-A0 Method Evidence #42318706983](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42318706983) concluyó **SUCCESS**. Las suites: **11** pruebas de política de evidencias, **6** de dependencias, **7** de mapa P02, **9** de workspace aislado, **5** de recursos persistentes/preflight y **7** de política de ejecución = **45 pruebas aprobadas**.

Los verificadores indicaron **63/63 scripts originales intactos**, 2 perfiles candidatos en política, **0 aprobados para ejecución automática**, caché persistente separada y política de limpieza tras recibo de resultados. La comprobación `docker compose ... config --quiet` finalizó correctamente.

**Alcance exacto:** son pruebas de fixtures y contratos. No se compiló la imagen Docker, no se ejecutaron APK reales y no se habilitó el análisis APK desde Android ni el VPS. Esas condiciones siguen pendientes para A4/A5/A9.

## F7-A0-P04 — Resultados y checkpoints (2026-11-06)

**IMPLEMENTACIÓN DE CONTRATOS, NO DESPLEGADA:** `cloud/apk_analysis/checkpoint_journal.py` registra checkpoints de solo metadatos con números, SHA-256 encadenados y commits atómicos/fsync, verificación de resultado final a través del almacenamiento futuro y lectura segura para Android sin datos sensibles. Nuevos esquemas `checkpoint-event.v1`, `result-event.v1`, `user-progress.v1` se mantienen por protocolo, sin historial por versión Android. Pruebas negativas de corrupción, crash, privilegios, integridad e idempotencia en CI. **P04 parcial** hasta A4/A5/A9 y pruebas reales de APK autorizados. [Documento P04](FASE_7_A0_P04_RESULTADOS_Y_CHECKPOINTS_2026_11_06.md). Los 63 scripts funcionales se conservan intactos.


### CI P04 verificado

[F7-A0 Method Evidence — ejecución 42323587447](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42323587447) concluyó **SUCCESS** en el commit `aec3fdf90f288e7bd85e9f931cbc532aa2e93aad`. Pruebas: 11 evidencia + 6 dependencias + 7 mapa P02 + 9 workspace + 5 preflight + 7 política P03 + 20 checkpoint journal + 4 esquemas = **69 pruebas aprobadas**.

**Confirmación de alcance:** no se ejecutaron APK reales ni herramientas de descifrado; el backend cifrado de objetos y la prueba de extremo a extremo siguen pendientes para A4/A5/A9. P04 queda **PARCIAL**, con contratos y pruebas cerrados pero integración productiva pendiente. Los JSON schemas se versionan por protocolo, no por versión de SP-DECODE Android.

## F7-A0-P05 — Corpus APK/APKS y límites (2026-11-06)

**EN PRUEBAS CI, NO PRODUCCIÓN:** se añadió `cloud/apk_analysis/input_gate.py` para validar límites y estructura ZIP, `tests/test_a0_apk_input_limits.py` con 21 pruebas adversas, compilador de APK firmado temporal `scripts/ci/build_p05_owned_apk.sh` y workflow `f7-a0-p05-apk-lab.yml` para ejecutar el inspector original en un sandbox Docker offline. Los APK, llaves temporales y salidas no se guardan en Git. Pendientes: muestras VPN autorizadas reales, split APKS instalables, decompilación JADX y ABI/ELF, cuotas y carga, integración A4/A5/A9. Los 63 scripts se conservaron. [Plan/resultados P05](FASE_7_A0_P05_CORPUS_APK_APKS_Y_LIMITES_2026_11_06.md).


### Incidencia real y corrección del entorno P05

- P05 lab compilado/firmado propio, inspector APK+APKS, Docker offline: [run 42325768902](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42325768902) **SUCCESS**.
- Precarga JADX falló por tmpfs de mantenimiento (64 MB; Errno 28), no por herramienta funcional: [run 42326083344](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42326083344). Se elevó **solo** precarga a 128 MB, sin modificar scripts o workers VPN.
- Revalidación en [run 42326350743](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42326350743); **P05 sigue PARCIAL** hasta comprobar su conclusión y ejecutar muestras APK de terceros autorizadas con pruebas de recuperación/ABI.

### F7-A0-P05 — Cierre de laboratorio, pendientes reales

[P05 lab #42326911352](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42326911352) **SUCCESS**: 21 casos adversos, APK propio firmado con DEX real, inspector original APK/APKS, precarga oficial SHA-256 de JADX 1.5.6 y reutilización offline, descompilación JADX con exit 0. [F7-A0 evidence #42326911348](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42326911348) **SUCCESS: 90 tests**. Sin alterar `scripts/apk_analysis/` ni decoders. Mantenimiento tmpfs=128 MiB y HOME/XDG en tmpfs para JADX; análisis mantiene red cerrada y filesystem raíz de solo lectura. **P05 PARCIAL** hasta APK VPN externo autorizado, APKS bundletool auténtico, ELF/ARM64 y estrés de cuotas/concurrencia/reinicio, pruebas con VM dedicada y conexión Android A4/A5/A9.

### P05 — Inyección de fallos acotada y recuperación (continuación)

**Estado: PARCIAL / SIN PRODUCCIÓN.** Nuevos `scripts/ci/p05_sandbox_faults.py` y `tests/test_a0_p05_failure_recovery.py`: observan límites del contenedor y ejercitan recuperación de procesos propios interrumpidos, escrituras fallidas y retención de soporte humano. `test_a0_apk_input_limits.py` excluye también `.zip` y `.xapk` expresamente. Se conectaron a `f7-a0-p05-apk-lab.yml` y `f7-a0-method-evidence.yml`; ejecutar y registrar resultados del último HEAD antes de cambiar cualquier estado a verificado.

**No realizado:** VPN APK externa con autorización y hashes; APKS real de bundletool; ARM64/ELF; concurrencia y reinicio de VM persistente; transferencia autenticada desde Android; cuotas por usuario; almacenamiento cifrado con verificación de tenant; automatización de 63 métodos; atención humana y cobro end-to-end. Los 63 scripts siguen intocados. Una prueba en runner CI no valida hardware VPS ni habilita ejecución desatendida.

### Gate de evidencias ampliado: 95 pruebas

[F7-A0 Method Evidence, run 42330901411](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42330901411), commit `bf6658398bedefcfea567d40d19c6454558ec17b`: **SUCCESS**. En logs: 11 + 6 + 7 + 9 + 5 + 7 + 20 + 4 + 22 + 4 = **95 pruebas** en diez suites, con 22 casos adversos de formato y 4 de recuperación. El mapa dinámico confirma `tools=63 unchanged=63 python=61 js=2 approved=0`. Las extensiones `.zip`/`.xapk` quedan rechazadas en el gate de servidor; la aplicación Android todavía no tiene la nueva subida habilitada. **No se otorga autorización para automatización de esas herramientas.**

### Verificación final del corpus de prueba (sin despliegue)

[F7-A0-P05 APK Lab run 42330901519](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDNDMDM/actions/runs/42330901519), sobre `bf665839`, **SUCCESS**: 22 pruebas adversas de APK/APKS, 4 pruebas de SIGKILL/recuperación/soporte humano, compilación y firmado propio, inspector original, JADX offline y los cinco controles Docker (seguridad/CPU/PID, ENOSPC, cgroup OOM, eliminación tras timeout, cache persistente verificada). [F7-A0 Method Evidence run 42330901411](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42330901411), mismo SHA, **SUCCESS, 95 pruebas**, 63/63 herramientas intactas. La ejecución general Validate SP-DECODE de este SHA se sigue rastreando por separado; no afirmar que haya terminado si continúa en cola.

**Decisión:** P05 permanece PARCIAL, sin análisis de APK ajenas, sin integración de subida Android y sin autorización de ejecución automática de herramientas. Se requiere corpus real consentido, bundletool auténtico, ARM64/ELF, estrés concurrencia/reinicio de VM y endpoints A4/A5/A9 antes de un cierre.

## F7-A0-P06 — Ampliación de cobertura y legado (continuación)

**Estado PARCIAL — revisión CI.** Nuevo `scripts/ci/check_a0_p06_coverage.py` con inventario de SHA-256 por fuente y dependencias/importaciones estáticas en decoders Python, apps VPN, worker Cloud, exportadores, módulos Cloud web y rutas API de métodos; cambio de método exige expediente actualizado en la misma PR y marca consumidores transitivos enlazados. Las importaciones dinámicas no resueltas se reportan como incertidumbre, sin presentarlas como cobertura completa.

Se registraron **78 carpetas legadas** en `analysis/platform/apk-tooling/legacy_provider_baseline.v1.json` con `LEGACY_UNREVIEWED`; ninguna herramienta aprobada ni bypass automático. Las 63 herramientas originales permanecen sin cambios. `tests/test_a0_p06_coverage.py` contiene 12 pruebas unitarias sintéticas; gate añadido al workflow `f7-a0-method-evidence.yml`. Documento: [F7-A0-P06](FASE_7_A0_P06_COBERTURA_GATE_Y_LEGADO_2026_11_06.md).

**Incidencia del primer CI:** el test P06 pasó 12 casos, pero el ejecutable lanzado por su ruta directa no hallaba `scripts` en `sys.path`; corregido acotadamente en commit `92fae370` sin tocar los decodificadores. Confirmar nueva ejecución antes de considerar el gate validado. **Pendientes:** revisión de rutas dinámicas/legado, distribuciones transitivas y licencias P01, PR real de prueba y protección de rama P07. P06/A0 y el análisis APK automático NO están completos.

## F7-A0-P06 — Diagnóstico corregido y validado en CI de PR #110

La versión inicial del gate P06 comparaba todos los cambios acumulados desde `main` en la PR #110 (144 commits), por lo que consideraba nuevas siete modificaciones Cloud históricas. Se corrigió con `post_cutover_changed_paths` (SHA de corte fijo **4fddee8924e58a9d1e6476974e9b7a9adda3e495**): se audita la PR completa, pero la exigencia documental se aplica únicamente a la intersección con archivos modificados después del corte. El SHA real del head debe tener el corte como ancestro; un corte o registro alterado falla de modo cerrado.

**CI real confirmado:** [F7-A0 Pull Request 42335831332](https://github.com/gokussj092/NSKSDKLDLDMDNDNDNNDNDNDNDNDNDNDNDNDNDNDNDMDM/actions/runs/42335831332) SUCCESS; [Push 42335826786](https://github.com/gokussj092/NSKSDKLDLDMDNDNDNNDNDNDNDNDNDNDNDNDNDNDMDM/actions/runs/42335826786) SUCCESS, en commit `4e9093c7`: 17 pruebas P06 pasan y los dos gates sobre PR completos pasan; inventario 486 fuentes/399 candidatos, 63 herramientas originales intactas y 0 aprobaciones automáticas. Un nuevo cambio futuro del método legacy sigue bloqueado sin dossier. P06 continúa PARCIAL por revisión de indirectos/ABI/licencias.

## F7-A0-P07 — Control requerido de GitHub y protección de main

**Estado PARCIAL — protección remota NO activa**. Consulta GitHub real: `main.protected=false`, `feat/nuevas-integraciones.protected=false`; reglasets del repositorio `[]`. La lectura detallada de `/branches/main/protection` devuelve 403 (sin permiso de administración de protección en integración). Los dos contextos a exigir en `main` son `evidence-gate` y `validate`.

Se integró un auditor P07 de configuración offline y tests negativos de wiring (sin secretos, sin API ni editar protección). Se mantienen las pruebas de no bypass del corte P06. Pendientes: resultado CI del último commit P07, activación en Settings por administrador, lectura posterior de `protected=true` y comprobación real de merge bloqueado ante un gate rojo. **Un workflow SUCCESS por sí solo no equivale a check requerido**.

[Documentación P07 con procedimiento y evidencias](FASE_7_A0_P07_REQUIRED_CHECK_PROTECCION_2026_11_06.md). No se ha hecho merge, otra rama ni despliegue.

## F7-A0-P08 — Regresión independiente de formatos y consumidores

**Estado:** implementación integrada, CI P08 independiente pendiente de resultado final. Se añadieron `analysis/platform/apk-tooling/p08_regression_matrix.v1.json` (19 suites existentes; 12 Python + 7 Node, mínimo 96 casos), `scripts/ci/run_a0_p08_regression.py`, `tests/test_a0_p08_regression.py` (16 casos de seguridad y detección de cambios) y `.github/workflows/f7-a0-p08-regression.yml` con jobs separados Python y Cloud web. La matriz cubre archivos/texto, catálogos, exportación unlocked y transporte; ejecuta los códigos actuales con fixtures existentes, comprueba hashes antes/después y falla si se omite una suite o se reduce su número de pruebas. Los 63 scripts originales quedan sin modificaciones.

**Limitación de evidencia:** los fixtures sintéticos/sanitizados son regresión efectiva de código de producción, NO prueba de APK de tercero, descargas reales ni Android→Cloud E2E. No se otorgó autorización a herramientas ni se alteró servidor productivo. Ver [documentación P08](FASE_7_A0_P08_REGRESION_FORMATOS_CONSUMIDORES_2026_11_06.md).

**Decisión P07:** el propietario mantiene GitHub Actions y revisión manual de todas las validaciones; Branch Protection **opcional y aplazada**, sin bloquear P08/P09 ni fingir que existe regla requerida. [Registro P07](FASE_7_A0_P07_REQUIRED_CHECK_PROTECCION_2026_11_06.md).
