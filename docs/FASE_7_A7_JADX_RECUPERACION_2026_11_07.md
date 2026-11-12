# F7-A7 — Recuperación JADX Lite y análisis guiado en el servidor

**Rama:** \`feat/nuevas-integraciones\`. **Fecha:** 2026-11-07.  
**Estado:** cambios implementados en rama; CI y pruebas en VPS deben verificarse de forma independiente. Ninguna APK Android se recompiló.

## Restricciones invariables

- VPS del operador: 3.7 GiB RAM, 2 vCPU; perfil \`JADX_LITE\` del contenedor \`apk-tools\` (límite Docker 1152 MB, 0.8 vCPU) y JVM \`-Xmx512m\` con un hilo. No lanzar 63 procesos.
- Una APK o APKS por vez y **100,000,000 bytes** máximos: los gates \`input_gate\` y \`qa_service\` existentes siguen siendo los responsables.
- Red privada, rootfs read-only, UID 65532, sin secretos HPKE ni conexión de red externa desde el proceso de análisis. JADX 1.5.6 fijado por SHA-256 se instala en build.
- Ghidra **NO** se ejecuta en Lite. En el perfil avanzado se exige además \`SPDECODE_APK_QA_GHIDRA=enabled\` explícito; no establecer esa variable en este VPS.
- Los métodos de descifrado de archivos, textos, catálogos VPN y sus pruebas existentes no se modificaron.

## Subfases

| Subfase | Implementado en código | Validación/pending |
|---|---|---|
| P01 diagnóstico JADX | \`qa_jadx_recovery.diagnose_termination\`: clasificación categórica de heap, disco, DEX, Java, permisos, timeout, inicio, error desconocido; no devuelve líneas de logs | Clasificación heurística; se requieren casos reales diversos |
| P02 reintentos | Si el primer JADX falla, extrae hasta cuatro DEX raíz, máximo 40 MiB por DEX y 96 MiB acumulados. Secuencia \`simple\` y solo si falla \`fallback\`; 75 s por intento | APK con más de 4 DEX o DEX muy grandes conserva omisiones; no afirmar cobertura total |
| P03 63 herramientas | \`qa_tool_plan.py\` referencia 63 rutas originales, 61 Python + 2 JS; selecciona por DEX/ELF/ARM64 los **candidatos para revisión**, nunca los importa ni ejecuta | Todos siguen sin autorización individual automática, salvo herramientas integradas específicamente como los parsers existentes y JADX |
| P04 hallazgos | \`qa_static\` añade \`methodEvidence\` correlacionando indicadores DEX, ELF, nombres de métodos y evidencia JADX de recuperación | No es grafo completo de llamadas, no recupera claves ni acredita métodos VPN |
| P05 informe | \`analysis.tooling.jadx.failureCategory\`, \`recovery\` con DEX descubiertos, seleccionados, omitidos, motivos y detalle de intentos. Se preservan resúmenes de fuentes de intentos fallidos | El scratch se borra al cerrar trabajo; no se guardan fuentes ni logs sensibles en el reporte |
| P06 regresión | \`tests/test_f7_a7_recovery.py\` y workflow \`f7-a7-server.yml\` (unitarios + JVM21/JADX real con código propio) | No se dispone de las APK/APKS privadas del usuario en el runner ni de acceso SSH al VPS |

## Contrato del informe

El primer intento conserva los campos históricos \`jadx.status\`, \`terminationReason\`, \`completed\`, \`sourceFilesInspected\`, \`candidateCallSites\`. Los reintentos añaden \`jadx.recovery\`: \`dexDiscovered\`, \`dexSelected\`, \`dexSkipped\`, \`dexTooLarge\`, \`dexRecovered\`, \`attempts\` (modo, categoría de error, duración límite, éxito y fuentes resumidas) y señales sanitizadas.

**Regla de honestidad:** si \`base.apk\` falla y se obtienen DEX parciales, \`jadx.status=PARTIAL_OUTPUT\`, \`jadxExecuted=false\`, \`methodValidated=false\`. Una salida Java existente no demuestra método criptográfico funcional ni cobertura de todos los DEX. Los indicadores por intentos pueden duplicarse con el primer intento y llevan \`sourceReferencesMayOverlapRetries\`.

\`analysis.toolPlan\` diferencia descubrimiento de herramientas de aprobación de ejecución. \`analysis.methodEvidence\` solo conecta referencias **estáticas**; nunca devuelve código generado, cadenas arbitrarias ni secretos. El escáner JADX deja de descartar todo `org.*` e `io.*`: solo excluye subárboles de bibliotecas conocidos. También prueba modo alternativo si el proceso sale con código cero pero no produce fuente útil. La selección de hallazgos JADX continúa limitada a 48 elementos; esta cobertura **no es un inventario exhaustivo** y debe ampliarse mediante un esquema de exportación auditado si fuera requerido.

## Reproducción

Desde raíz de la rama:

\`\`\`bash
python -m compileall -q cloud/apk_analysis
python -m unittest tests.test_f7_a7_recovery tests.test_f7_apk_qa_jadx_refs tests.test_f7_apk_qa_deep tests.test_f7_apk_qa_tooling_policy tests.test_f7_apk_qa_tool_rpc -v
bash -n cloud/infra/vps/spdecodectl
docker compose --profile apk-qa --profile apk-qa-tools -f cloud/compose.yaml config --quiet
docker build -f cloud/apk_analysis/Dockerfile.qa-lite -t spdecode-f7-a7-lite .
\`\`\`

CI añade una prueba de decompilación efectiva de **un JAR Java propio** y sin Ghidra, nunca de una APK privada de terceros. Su verde NO valida el descifrado de una VPN.

**Tras comprobar GitHub Actions**, despliegue manual del servidor según el procedimiento existente de F7-A5:

\`\`\`bash
sudo spdecode update all feat/nuevas-integraciones
sudo spdecode apk-qa enable
sudo spdecode apk-qa enable-lite
sudo spdecode apk-qa status
\`\`\`

No ejecutar \`enable-tools\` en 3.7 GiB RAM. Vigilar presión RAM, CPU, disco y tiempo total; si falla, conservar el JSON parcial antes de reiniciar. No hay nueva APK Android asociada a esta fase.

## Pendientes de aceptación

1. Verificar que workflow de F7-A7, F7-A0, QA y Cloud se completan exitosamente en el **commit final**, sin asumir que un check en cola sea verde.
2. Probar en VPS una APK y una APKS autorizadas de menos de 100 MB; identificar categoría de fallo y confirmar recuperación sobre DEX real.
3. Confirmar que una solicitud simultánea recibe \`WORKER_BUSY\` y no sobrepasa la memoria disponible.
4. Evaluar cada uno de los 63 scripts por dependencias, ABI, red, permisos, inputs, licencias y riesgos antes de ejecutar cualquiera; nunca conceder permisos globales por el nombre del script.
5. Ampliar análisis de flujo de datos, grafo de llamadas y cobertura completa por DEX sin incluir secretos en informes; revisar límite de 48 sitios.
6. Publicar evidencias de cada APK/build bajo \`analysis/<package>/<build>/\` con la política \`METHOD_EVIDENCE_POLICY.md\`. Sin muestras reales, los resultados siguen PENDING.
