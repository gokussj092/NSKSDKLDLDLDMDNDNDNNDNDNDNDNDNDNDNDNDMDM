# F7-A0-P02 — Matriz dinámica de herramientas y consumidores

**Rama:** `feat/nuevas-integraciones`. **Estado:** `PARCIAL — MATRIZ ESTÁTICA EN CI` (2026-11-06).

## Alcance acordado

Las 63 herramientas que ha utilizado Work permanecen **intactas**. Se analizan los archivos como texto/AST de Python; no se importan ni ejecutan, no se hace HTTP, no se cargan APKs, no se ejecuta Java/JADX/Frida/ADB ni se modifica ningún método de descifrado.

La matriz se **regenera con el estado actual del repositorio**, sin historiales rígidos por versión de Android. El workflow F7-A0 publica el artefacto `f7-a0-usage.json` de su ejecución y registra las herramientas sin aprobación automática.

## Campos por herramienta

| Elemento | Interpretación |
|---|---|
| Ruta, tamaño, Git blob SHA-1 y SHA-256 | Integridad exacta de la fuente existente, comparada contra el inventario |
| Tipo PYTHON/JAVASCRIPT y parse_status | Parseo Python AST o inspección textual JS sin ejecución |
| cli_flags y cli_positionals | Etiquetas literales argparse, **no** autorización para aceptar parámetros arbitrarios |
| external_imports y sibling_imports | Importaciones presentes en fuente, no paquetes importados por el auditor |
| static_signals | Posibles API de red, procesos, instrumentación, dispositivos Android, escritura, binarios ELF, emulación, criptografía e imágenes |
| abi_literal_hints | Menciones ARM64/x86_64; **no** compatibilidad de arquitectura certificada |
| documented_app_build_references | Dossiers de aplicación/build con referencias al nombre de la herramienta |
| test_source_references | Pruebas que mencionan la herramienta; **no** equivalen a prueba de ejecución |
| references | Archivo y número de línea de referencias; no copia comandos, secretos, credenciales ni resultados |
| consumer_confidence | Solo referencias estáticas, o sin referencias explícitas; **no** es un mapa completo de ejecución |

**Importante:** el registro fuente `analysis/platform/apk-tooling/tool_sources.v1.json` no se cuenta como referencia de uso, ya que contiene los 63 nombres por definición. Los usos detectados en la documentación son evidencia de mención, no de que todas las funcionalidades hayan funcionado en un APK reciente.

## Ejecución reproducible

```bash
python -m unittest discover -s tests -p 'test_a0_tool_usage.py' -v
python scripts/ci/map_apk_tool_usage.py --output /tmp/f7-a0-usage.json
```

El mapa se publica mediante `.github/workflows/f7-a0-method-evidence.yml` como artefacto de GitHub Actions. El auditor falla si algún script cambia de contenido sin actualizar el inventario correspondiente y **nunca** activa ejecución desatendida.

## Pendientes para cerrar P02

1. Revisar manualmente las herramientas sin referencias directas, incluso si el trabajo anterior de Work demuestra que funcionan. No inventar una relación de consumidores basándose solo en nombres.
2. Incorporar trazabilidad de usos indirectos por wrappers y plugins que no citan directamente el nombre del archivo.
3. Verificar por aplicación/build las capacidades reales de cada método mediante la documentación/outputs previamente comprobados y pruebas controladas, distinguiendo sintético de real.
4. Registrar ABI, requisitos de red, parámetros seguros y límites de recursos **por candidato**. Convertirlos en políticas de ejecución autorizada solo en **P03**.
5. Mantener P01 abierto para locks transitivos, wheel/ABI y requisitos de licencia ya identificados, sin cambiar versiones que funcionan.

**No declarar P02 completa ni el nuevo servicio de análisis APK al 100%** por el resultado de este escaneo. Se necesita integrar worker, pruebas reales y soporte de etapas posteriores.


### Validación verificada en GitHub Actions

[F7-A0 Method Evidence — run 42316597610](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42316597610) concluyó **SUCCESS** sobre el commit `ca2f699`. Se aprobaron **11 pruebas de evidencia, 6 de dependencias y 7 del nuevo mapa** (24 pruebas en estas tres suites).

El escaneo de P02 informó: **63 herramientas intactas**, 61 Python + 2 JavaScript, **63 mencionadas por al menos un archivo**, **8 con referencias explícitas en expedientes de app/build**, **22 con referencia explícita en pruebas**, 0 errores de parseo y **0 autorizaciones de ejecución automática**.

**La cifra 63 mencionadas no indica 63 herramientas en producción**: las referencias pueden proceder de documentación general. Los grupos de 8 y 22 contabilizan *herramientas con al menos una referencia*, no número de aplicaciones ni pruebas exitosas.

El workflow publicó el artefacto `f7-a0-evidence` (incluye `f7-a0-usage.json`), disponible desde la página de la ejecución durante su período de retención. Este informe es generado automáticamente, no un historial fijo por versión.

**P02 sigue PARCIAL:** faltan análisis de consumidores indirectos y verificación de las capacidades reales por aplicación; estas auditorías no alteran ni certifican los métodos existentes.
