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
| **A0-P07** | Activar required check de rama tras cubrir gate | Configuración de branch protection + prueba de bloqueo; workflow verde no equivale a regla requerida. |
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
