# GOOD VPN 3.0 — RESULTS

Fecha de verificación: 2026-11-17. Entorno: Python 3.12.3 del sistema.

## Estado por vía

- **catalog**: VERIFIED — Version 21.8 en vivo abre; 13 servidores, 14
  payloads, `undecoded_fields: []`. Re-corrida en vivo byte por byte
  idéntica al `live.json` entregado.
- **files**: VERIFIED (formato = cuerpo remoto) — el cuerpo vivo
  guardado abre con `Good_VPN_archivos.py`; falta un `profile.json`
  real extraído de un teléfono.
- **text**: NOT_APPLICABLE — sin esquema URI propio; vmess/vless/
  trojan/ss solo dentro de la librería v2rayNG empaquetada.
- **export**: PENDING — sin compartir por código en 3.0.

## Catálogo en vivo

Versión 21.8, 13 servidores (todos con bandera `th`), 14 payloads
(Networks), `setOpenVPN` vacío a nivel superior. JSON descifrado
39.761 B; cuerpo cifrado 69.064 B. `Message` es el aviso de
actualización fechado 16/11/26.

## Self-tests y verificaciones del script operativo

- `Good_VPN_archivos.py --self-test`: 3/3 ok (round-trip sintético
  cifrar → descifrar, 3 documentos).
- `Good_VPN.py work/newgood.json --summary` (cuerpo vivo guardado):
  `{"Version": "21.8", "Servers": 13, "Networks": 14,
  "undecoded_fields": []}`.
- `Good_VPN.py` no tiene `--self-test` (ver ANALYSIS.md,
  limitaciones).

## Re-corrida en vivo (byte por byte)

- `Good_VPN.py --url -o /tmp/live-good-rerun.json`: **byte por byte
  idéntica** a `~/workspace/catalogs/goodvpn/live.json` (SHA-256
  `0aabf2cd01bdb9278650096f355490b99b41b7f9412c109436110275a975bf80`).
  Tiempo de la descarga + descifrado: ~0,9 s (muy por debajo del tope
  de 20 s del worker y del presupuesto de 120 s de catálogo).
- Nota: un intento intermedio escribió el `--summary` (recuentos) en el
  archivo de salida y falló el `cmp` por mi error de invocación, no del
  script; repetido limpio (sin `--summary`, destino borrado antes por
  `O_EXCL`), el `cmp` es idéntico. Además, pasar el JSON ya descifrado
  como entrada al script devuelve `FORMAT_ERROR` correctamente: espera
  el cuerpo cifrado Base64, no el JSON.

## Rutas del servidor simuladas en proceso

Simulación sin red, con los bytes guardados `work/newgood.json`
(SHA-256 `c822a825…`):

- Camino supplied genérico (`module.decode(raw)`): **==** `live.json`
  (0,06 s), `undecoded_fields(doc)`: `[]`.
- Camino C8 (`module.run(raw)` → str): **==** `live.json` (0,06 s).
- Camino archivo (`Good_VPN_archivos.decode(raw)`): versión 21.8, 13
  servidores, 14 redes.
- Entrada inválida (`run(b'xxxx')` / `Good_VPN_archivos.run(b'xxxx')`):
  devuelve `None`.

## Tests del expediente

`python3 -m unittest discover -s tests -v` — ver salida en la entrega.
Vectores SINTÉTICOS con claves de prueba (no reales): positivo
(round-trip), negativos (vacío, Base64 inválido, clave equivocada,
truncado) y esquema del fixture. Los fixtures son sintéticos
(`tests/fixtures/synthetic_catalog.json`, hosts 203.0.113.0/24 y
example.org); un fixture sintético demuestra la lógica implementada,
NO prueba compatibilidad con una versión real ni conectividad remota.

## Qué se probó con oráculo independiente

- XXTEA puro verificado con round-trip cifrar → descifrar en los
  self-tests y contra el cuerpo vivo guardado (hash en MANIFEST.json).
- Descargas en vivo verificadas dos veces (entrega original 2026-11-17
  y re-corrida byte por byte el mismo día).

## Clasificación de evidencia

- `VERIFIED`: descarga en vivo verificada o archivo real abierto.
- `VERIFIED_SYNTHETIC`: solo muestra sintética sellada con el mismo
  método.
- `PARTIAL`: vía que abre pero con valores que no descifran o pasos
  pendientes (ver limitaciones).
- `PENDING` / `REQUIRES_DEVICE`: falta muestra real de teléfono o
  dispositivo registrado.
- `NOT_APPLICABLE`: la app no tiene esa vía (sin esquema propio, sin
  formato propio).
