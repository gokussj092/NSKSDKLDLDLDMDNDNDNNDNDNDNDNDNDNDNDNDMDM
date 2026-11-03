# analysis/ — Archivo obligatorio de investigación SP-DECODE

**NUEVA REGLA PERMANENTE DE TRABAJO (2026-11-02):** Toda aplicación nueva, nuevo método o actualización de un método ya existente debe guardar sus **scripts utilizados, herramientas, comandos, pruebas, metadatos de la APK y evidencias** en un expediente propio dentro de esta carpeta ANTES de anunciar el método como integrado/verificado.

La política normativa completa es [METHOD_EVIDENCE_POLICY.md](METHOD_EVIDENCE_POLICY.md). Es obligatoria para investigadores, colaboradores y asistentes de IA del repositorio.

## Ubicación

- `analysis/<package_android>/<version_code>/MANIFEST.json`
- `analysis/<package_android>/<version_code>/ANALYSIS.md`
- `analysis/<package_android>/<version_code>/REPRODUCE.md`
- `analysis/<package_android>/<version_code>/RESULTS.md`
- `analysis/<package_android>/<version_code>/tools/` — **scripts de investigación propios empleados**, no solo el código final
- `analysis/<package_android>/<version_code>/tests/` — pruebas/fixtures sin secretos

Los expedientes enlazan al decodificador operativo en `decoders/Python/apps/` y a las utilidades compartidas en `scripts/apk_analysis/`; NO reemplazan ni eliminan esas rutas. Si se usó una herramienta compartida, registrar versión, ruta/hash y guardar un script/wrapper reproducible de la invocación por aplicación. Si se utilizó un script creado para la investigación, guardar el script físicamente en tools/.

Un resultado **no confirmado** también se archiva, con estado PENDING, PARTIAL o FAILED y las razones reales. No inventar éxito. No subir APK privado, datos de terceros, cuentas, claves ni archivos descifrados sensibles.

**La obligación documental ya está vigente; el validador automático de GitHub CI y la protección de rama están pendientes**, definidos en la política. Sin el expediente, los métodos nuevos NO se consideran finalizados.

## Proyecto futuro que consumirá estas evidencias

[Análisis automático de APK — dos salidas](../docs/FASE_7_APK_AUTOANALISIS_DOS_SALIDAS_PENDING_2026_11_02.md): A) informe estructurado con metadatos y hallazgos; B) código propuesto por IA más pruebas de validación. Ambas funciones permanecen deshabilitadas y pendientes de desarrollo.

El archivo histórico [SOCKSIP_VER8_VER7_VER6_STUDY.md](SOCKSIP_VER8_VER7_VER6_STUDY.md) se conserva; no es un expediente por paquete/build de la nueva política.
