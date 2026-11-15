# F7-A0 — Inventario de herramientas y control de evidencias (2026-11-06)

**Rama de trabajo:** `feat/nuevas-integraciones`  
**Estado:** `PARTIAL / IMPLEMENTATION_STARTED`. El inventario y el validador están en código; NO está aprobada la ejecución automática de herramientas, ni se considera cerrada F7-A0.  
**Línea base de lectura:** `96ab053f44dcff60d2cbf9ea79e4cfeaec7a7b69`.

## Alcance observado

- `scripts/apk_analysis/`: **63 archivos .py/.js** en el árbol Git de la línea base, conservados intactos. `tool_sources.v1.json` almacena ruta, bytes y OID de blob Git por herramienta. Un OID de Git **no** es un checksum SHA-256; el script local calcula también SHA-256 sobre bytes reales en un checkout.
- `analysis/platform/apk-tooling/dependencies.v1.json`: inventario de siete paquetes fijados, un runtime y JADX, con licencia/distribución pendientes de revisión.
- `scripts/apk_analysis/requirements.txt`: siete dependencias Python directas con versión exacta en ese archivo. El pin no demuestra ausencia de problemas de cadena de suministro ni pin de todas sus transitivas.
- `analysis/`: **11 expedientes de aplicaciones/build con MANIFEST.json** y estructura documental básica presente (ANALYSIS, REPRODUCE, RESULTS, DEPENDENCIES, lockfile y al menos un archivo en tools/ y tests/). Un expediente estructuralmente presente **no** es una certificación técnica, jurídica, de dependencias o de ejecución automática.
- Otras carpetas con manifiesto: `analysis/_intake/mediafire-ypaiywpzrvslef1/` y `analysis/platform/catalog-results/2026-11-05/`. Son artefactos de ingreso/plataforma, no paquetes Android, por lo que el validador de expedientes por package/build no los debe tratar como fallos de aplicación.
- Dos expedientes de aplicación necesitan conservarse como **no verificados en conjunto**: `com.tunneldoom.http/432` está PENDING y `noob.arpro.vpn/2` está PARTIAL. La presencia de documentación no modifica esos estados.
- No se descargó ningún catálogo, APK externa ni se ejecutaron scripts de terceros para producir este inventario.

## Archivos implementados

- `analysis/platform/apk-tooling/tool_sources.v1.json`: baseline inmutable de identidades de fuente y aprobación UNREVIEWED.
- `scripts/ci/check_method_evidence.py`: auditoría local (stdlib), resumen de dependencias fijadas, SHA-256 de scripts y registro de expedientes; chequeo de cambios de proveedores/herramientas con problemas de evidencia.
- `tests/test_method_evidence_a0.py`: pruebas offline con directorios y manifiestos sintéticos; sin conexión a terceros.
- `.github/workflows/f7-a0-method-evidence.yml`: job independiente de inventario y tests en la rama; gate de cambios en pull requests contra el SHA base, con reporte sanitizado como artefacto.
- Este documento: decisiones, alcance, carencias y procedimiento.

## Reproducir desde la raíz del repositorio

```bash
python -m unittest discover -s tests -p 'test_method_evidence_a0.py' -v

python scripts/ci/check_method_evidence.py \
  --output /tmp/f7-a0-inventory.json

# Simula el gate de una PR contra la base de comparación conocida:
python scripts/ci/check_method_evidence.py \
  --enforce --base-ref origin/main \
  --output /tmp/f7-a0-gate.json
```

El último comando requiere que la referencia exista en el checkout y puede bloquear un cambio por expediente ausente. En CI usa el SHA concreto de la base de la PR. El informe de inventario **no** contiene muestras/secretos ni contenidos de métodos.

### Pruebas locales aisladas realizadas

**11 tests, 11 OK** en el entorno de análisis, usando exclusivamente Python estándar y fixtures generados por cada test. Cobertura: hashes y dependencias, proveedor con/sin dossier, proveedor nuevo, faltantes de documentos/tests, protocolo de catálogo, cambios de herramientas compartidas, baseline obsoleta, documentación sola, validación de rutas, JSON inválido y package/build incongruente.

**Verificado en GitHub Actions:** [F7-A0 Method Evidence, run 42303343370, intento 2](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42303343370), estado **SUCCESS**. Logs: `Ran 11 tests ... OK`, `tools=63 pinned-deps=7 app-dossiers=11 structurally-complete=11`. Pasaron los pasos de tests, inventario y comprobación de PR. **La validación general NO está verde:** [Validate SP-DECODE, run 42303343453, intento 2](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42303343453), **FAILURE** con 13 failures, 3 errors y 9 skipped en 1,206 tests de la suite. Se documenta en QA-01 y no se atribuye causalidad a F7-A0 sin investigación. Las pruebas sintéticas de este gate NO prueban descifrado, descarga HTTP, integridad de una APK ni paridad con un motor Android.

## Modelo de aprobación y fronteras

1. Todos los scripts inventariados continúan `UNREVIEWED` para ejecución automatizada. Nunca usar el listado como allowlist ejecutable.
2. Un cambio en `scripts/apk_analysis/` exige actualizar la fuente del inventario; un cambio en un proveedor exige un expediente por package/build revisado en el mismo conjunto de cambios. El comprobador identifica algunos archivos genéricos del catálogo, pero **todavía no cubre todas las rutas y plugins dinámicos**.
3. Ningún valor de `status: VERIFIED` de un expediente equivale automáticamente a `APPROVED_FOR_AUTO_EXECUTION`. Los modos A/B del futuro analizador requieren revisión específica de licencia, dependencias, comportamiento, aislamiento y uso de red.
4. El nuevo código de F7-A0 no llama a `inspect_apk.py`, JADX, ADB, Frida ni a ningún binario de una APK; solo lee metadatos locales para su auditoría.

**Matriz actualizada de todas las subfases, pendientes y handoff:** [FASE_7_SEGUIMIENTO_ESTADOS_Y_PENDIENTES_2026_11_06.md](FASE_7_SEGUIMIENTO_ESTADOS_Y_PENDIENTES_2026_11_06.md). Se registra F7-A0 como PARCIAL, no DONE.

**F7-A0-P01 (parcial):** [auditoría de dependencias y licencias](FASE_7_A0_P01_AUDITORIA_DEPENDENCIAS_2026_11_06.md). Los 63 scripts siguen intactos; falta resolver wheels reales, transitivas y licencias.

**Avance P02:** [matriz dinámica de herramientas y consumidores](FASE_7_A0_P02_MAPA_HERRAMIENTAS_2026_11_06.md). La matriz se regenera desde las fuentes actuales; no ejecuta scripts. P02 sigue PARCIAL hasta confirmar usos indirectos y capacidades comprobadas.

**Avance P03:** [entorno aislado y persistencia de recursos](FASE_7_A0_P03_ENTORNO_PERSISTENTE_2026_11_06.md). Base host-only y tests sintéticos, sin integración Android ni habilitación de herramientas reales; **P03 PARCIAL**.

**Avance P04:** [esquemas de checkpoints y resultados con diario durable](FASE_7_A0_P04_RESULTADOS_Y_CHECKPOINTS_2026_11_06.md). Contratos implementados con pruebas sintéticas, no habilitados en producción; requieren almacenamiento cifrado/transaccional y pruebas reales A4/A5.

**Avance P05:** [corpus generado y pruebas APK/APKS en sandbox](FASE_7_A0_P05_CORPUS_APK_APKS_Y_LIMITES_2026_11_06.md). P05 sigue PARCIAL hasta muestras autorizadas de terceros, bundletool splits reales, JADX y perfiles ARM64 probados.

**Avance P06:** [cobertura de rutas Cloud/worker/plugins y legado](FASE_7_A0_P06_COBERTURA_GATE_Y_LEGADO_2026_11_06.md). Nuevo inventario dinámico de SHA-256 de fuentes y dependencias/importaciones estáticas, gate de cambios y baseline explícita de 78 carpetas LEGACY_UNREVIEWED. Sin ejecución ni aprobación de herramientas; CI de P06 requiere confirmación del último run.

## Pendientes para cerrar F7-A0

- Revisión real de **licencias, procedencia, versiones y SHA-256 de distribuciones externas/transitivas** para cada herramienta, incluidas Java/Node/Unicorn/Frida/JADX si se utilizan. No atribuir aprobaciones ni hashes inventados.
- Asociar cada script con capacidades específicas, arquitectura, parámetros y riesgos; fijar adaptadores de ejecución permitidos, política de red y límites de CPU/memoria/IO. Probar por separado cada candidato en sandbox.
- Baseline gradual de proveedores heredados sin expediente y trazabilidad de **todas** las rutas de método Cloud/worker; ampliar el gate para reportar consumidores afectados por cambios de una herramienta compartida.
- Validar el informe en checkout completo y comprobar Actions; convertir el job en check requerido mediante protección de rama una vez que la cobertura sea suficiente. La existencia del workflow no modifica por sí sola la protección de rama.
- Corpus de APK/APKS propias/autorizadas: ZIP corrupto, múltiples DEX, ELF, manifiestos y límites; cobertura positiva/negativa, hashes y referencias independientes. No declarar un método VERIFIED_REAL por fixtures sintéticas.
- Decidir y formalizar contratos de checkpoint, reportes, consentimiento/privacidad y separación de datos del futuro worker F7-A5.

## Relación con F7-A1…A9

**No se ha empezado** OAuth, cuentas, billing, transferencia de APK, worker de análisis automático, IA, panel Soporte APK o nuevas pantallas Android. Se conserva la UI «Próximamente». No se han modificado decodificadores, flag de proveedores, API de producción ni VPS.

Reglas rectoras: [METHOD_EVIDENCE_POLICY.md](../analysis/METHOD_EVIDENCE_POLICY.md), [FASE_7_PLAN_IMPLEMENTACION_Y_QA](FASE_7_PLAN_IMPLEMENTACION_Y_QA_2026_11_04.md), [FASE_7_APK_AUTOANALISIS_DOS_SALIDAS](FASE_7_APK_AUTOANALISIS_DOS_SALIDAS_PENDING_2026_11_02.md).


### Validación CI de P01 (GitHub Actions)

[F7-A0 Method Evidence, run 42314608709](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42314608709), resultado **SUCCESS** (commit f263c3587e9cca8d9a87496b95cf9ab7880719b9). Ejecutados 11 tests de evidencia + 6 tests nuevos de metadatos. Inventario: 63 scripts, 7 pins directos, 11 dossiers. Verificador P01: 7 SDIST de referencia, 0 wheels instalados atestiguados y 0 autorizaciones automáticas. Estado P01 **PARCIAL**, pendiente wheel/ABI/transitivas/revisión jurídica. No implica fallo funcional de herramientas anteriores.


### Validación verificada en GitHub Actions

[F7-A0 Method Evidence — run 42316597610](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42316597610) concluyó **SUCCESS** sobre el commit `ca2f699`. Se aprobaron **11 pruebas de evidencia, 6 de dependencias y 7 del nuevo mapa** (24 pruebas en estas tres suites).

El escaneo de P02 informó: **63 herramientas intactas**, 61 Python + 2 JavaScript, **63 mencionadas por al menos un archivo**, **8 con referencias explícitas en expedientes de app/build**, **22 con referencia explícita en pruebas**, 0 errores de parseo y **0 autorizaciones de ejecución automática**.

**La cifra 63 mencionadas no indica 63 herramientas en producción**: las referencias pueden proceder de documentación general. Los grupos de 8 y 22 contabilizan *herramientas con al menos una referencia*, no número de aplicaciones ni pruebas exitosas.

El workflow publicó el artefacto `f7-a0-evidence` (incluye `f7-a0-usage.json`), disponible desde la página de la ejecución durante su período de retención. Este informe es generado automáticamente, no un historial fijo por versión.

**P02 sigue PARCIAL:** faltan análisis de consumidores indirectos y verificación de las capacidades reales por aplicación; estas auditorías no alteran ni certifican los métodos existentes.


### Resultados verificados en GitHub Actions (P03)

La ejecución [F7-A0 Method Evidence #42318706983](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42318706983) concluyó **SUCCESS**. Las suites: **11** pruebas de política de evidencias, **6** de dependencias, **7** de mapa P02, **9** de workspace aislado, **5** de recursos persistentes/preflight y **7** de política de ejecución = **45 pruebas aprobadas**.

Los verificadores indicaron **63/63 scripts originales intactos**, 2 perfiles candidatos en política, **0 aprobados para ejecución automática**, caché persistente separada y política de limpieza tras recibo de resultados. La comprobación `docker compose ... config --quiet` finalizó correctamente.

**Alcance exacto:** son pruebas de fixtures y contratos. No se compiló la imagen Docker, no se ejecutaron APK reales y no se habilitó el análisis APK desde Android ni el VPS. Esas condiciones siguen pendientes para A4/A5/A9.


### CI P04 verificado

[F7-A0 Method Evidence — ejecución 42323587447](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42323587447) concluyó **SUCCESS** en el commit `aec3fdf90f288e7bd85e9f931cbc532aa2e93aad`. Pruebas: 11 evidencia + 6 dependencias + 7 mapa P02 + 9 workspace + 5 preflight + 7 política P03 + 20 checkpoint journal + 4 esquemas = **69 pruebas aprobadas**.

**Confirmación de alcance:** no se ejecutaron APK reales ni herramientas de descifrado; el backend cifrado de objetos y la prueba de extremo a extremo siguen pendientes para A4/A5/A9. P04 queda **PARCIAL**, con contratos y pruebas cerrados pero integración productiva pendiente. Los JSON schemas se versionan por protocolo, no por versión de SP-DECODE Android.

**Verificación P05 de laboratorio:** [APK Lab 42326911352](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42326911352) **SUCCESS**, [Gate F7-A0 42326911348](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42326911348) **SUCCESS (90 pruebas)**. No se debe marcar el análisis APK de usuarios como listo: faltan corpus autorizado de terceros y E2E Android.

**Estado P07 (continuación):** [required checks y protección de `main`](FASE_7_A0_P07_REQUIRED_CHECK_PROTECCION_2026_11_06.md). Se confirmaron `main.protected=false`, branch protection no activa y rulesets vacíos; la integración conectada devuelve 403 al consultar reglas detalladas, sin permiso para activarlas. La regresión P06 sobre la PR #110 pasó en [42335831332](https://github.com/gokussj092/NSKSDKLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42335831332), sin modificar 63 scripts. La regla required check de GitHub sigue PENDIENTE de activación y prueba de bloqueo real.
