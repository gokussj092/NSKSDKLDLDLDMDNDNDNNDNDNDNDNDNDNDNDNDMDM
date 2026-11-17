# Fx Tunnel 4.8 — RESULTS

Fecha de verificación: 2026-11-17. Entorno: Python 3.12.3 del sistema
(solo stdlib).

## Estado por vía

- **catalog**: PARTIAL — empaquetado v10288 abre completo; en vivo sin
  URL (fallo honesto).
- **files**: VERIFIED_SYNTHETIC — `.fxt`: método verificado contra
  `libputils.so` propia y asset `server.psi` (22 entradas); self-test
  5/5. Falta un `.fxt` REAL exportado.
- **text**: NOT_APPLICABLE — sin esquema URI propio.
- **export**: PENDING — sin compartir por código, registro de
  dispositivo ni créditos en 4.8.

## Catálogo empaquetado

Version **10288**, 29 servidores libres, 0 premium / VIP / privados,
**1353 payloads**. Reproducción 2026-11-17: `Fx_Tunnel.py --apks
apks/base.apk` produce salida **byte-idéntica** a `bundled.json`
(SHA-256 `f8c3a909f6c10d45f65dc07e3c245f4ddc457751e76a48a73b4fe6d6161d9c64`).

## Catálogo en vivo

URL NO RECUPERADA (ver `live_probe.json` y ANALYSIS.md). No se
inventó ninguna URL ni se probó ninguna sustituta. El script soporta
`--url <URL>` explícita con la clave ya verificada.

## Archivos .fxt

`Fx_Tunnel_archivos.py --self-test`: `{"self_test": "pass",
"profiles": 5, "passed": 5, "field_counts": [15, 4, 3, 1, 2],
"server_psi_entries": 22}`, exit 0. Round-trip sintético 5/5 (15, 4,
3, 1 y 2 campos; incluye unicode/CESU-8, carácter fuera del BMP, NUL
embebido y valor de 5.000 caracteres; también con el hex en
mayúsculas). `py_compile` OK.

`--psi` sobre `extracted/base/assets/server.psi` reproduce
`server_psi.json`: 22 entradas, idéntico (`a==b` True).

## Tests del expediente

`python3 -m unittest discover -s tests -v` — ver salida en la entrega.
Vectores SINTÉTICOS con claves de prueba (ver `tools/xxtea_pure.py`):
round-trip XXTEA con clave de prueba, validación estructural del
catálogo (`_catalog_json`), round-trip `.fxt` sintético, negativos
(hex inválido, Base64 inválido, documento sin listas) y estructura del
fixture sintético. Un fixture sintético demuestra la lógica
implementada, NO prueba compatibilidad con una versión real ni
conectividad remota; eso lo prueban la reproducción del empaquetado
y el asset `server.psi` de arriba.
