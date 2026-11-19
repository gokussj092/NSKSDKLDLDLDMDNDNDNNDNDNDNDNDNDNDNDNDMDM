# SSC Custom (SSH Custom) — dev.epro.ssc

Matriz de builds y hallazgos. Un solo build estudiado.

| Build (versionCode) | Versión | Estado | Formatos | Notas |
| --- | --- | --- | --- | --- |
| 96 | 4.3.13 | **VERIFIED_SYNTHETIC** | `.ssc`, `ssc://` | En vivo en Play desde el 29-10-2026. Decodificador offline C++ + oráculo Python verificados por round-trip sintético (24/24 vs servidor, 12/12 vs C++). Falta una muestra real exportada por la app para pasar a VERIFIED. |

Detalle completo en `96/` (MANIFEST.json, ANALYSIS.md, REPRODUCE.md,
RESULTS.md, DEPENDENCIES.md, tools/, tests/).

Resumen del formato: ChaCha20 (variante DJB, nonce 64 bits, contador
desde 1) en 3 capas con claves fijas embebidas (L1/L2/L3) + JSON con
claves de una letra. 100% offline: sin servidor, sin red, sin cuenta.
Quirks del servidor reproducidos a propósito: en archivos de dos capas
los perfiles conservan las claves de una letra, y los campos internos
L3 de ≤16 hex quedan cifrados.
