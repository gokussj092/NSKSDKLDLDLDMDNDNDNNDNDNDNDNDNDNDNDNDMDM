# F7-A0 — Inventario de herramientas y control de evidencias (2026-11-06)

**Rama de trabajo:** `feat/nuevas-integraciones`  
**Estado:** `PARTIAL / IMPLEMENTATION_STARTED`. El inventario y el validador están en código; NO está aprobada la ejecución automática de herramientas, ni se considera cerrada F7-A0.  
**Línea base de lectura:** `96ab053f44dcff60d2cbf9ea79e4cfeaec7a7b69`.

## Alcance observado

- `scripts/apk_analysis/`: **63 archivos .py/.js** en el árbol Git de la línea base, conservados intactos. `tool_sources.v1.json` almacena ruta, bytes y OID de blob Git por herramienta. Un OID de Git **no** es un checksum SHA-256; el script local calcula también SHA-256 sobre bytes reales en un checkout.
- `scripts/apk_analysis/requirements.txt`: ocho dependencias Python directas con versión exacta en ese archivo. El pin no demuestra ausencia de problemas de cadena de suministro ni pin de todas sus transitivas.
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

**No corresponde afirmar ejecución verde de GitHub Actions ni de la suite completa del proyecto hasta consultar el resultado del run.** Las pruebas sintéticas de este gate NO prueban descifrado, descarga HTTP, integridad de una APK ni paridad con un motor Android.

## Modelo de aprobación y fronteras

1. Todos los scripts inventariados continúan `UNREVIEWED` para ejecución automatizada. Nunca usar el listado como allowlist ejecutable.
2. Un cambio en `scripts/apk_analysis/` exige actualizar la fuente del inventario; un cambio en un proveedor exige un expediente por package/build revisado en el mismo conjunto de cambios. El comprobador identifica algunos archivos genéricos del catálogo, pero **todavía no cubre todas las rutas y plugins dinámicos**.
3. Ningún valor de `status: VERIFIED` de un expediente equivale automáticamente a `APPROVED_FOR_AUTO_EXECUTION`. Los modos A/B del futuro analizador requieren revisión específica de licencia, dependencias, comportamiento, aislamiento y uso de red.
4. El nuevo código de F7-A0 no llama a `inspect_apk.py`, JADX, ADB, Frida ni a ningún binario de una APK; solo lee metadatos locales para su auditoría.

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
