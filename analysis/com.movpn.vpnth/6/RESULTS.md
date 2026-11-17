# MO VPN 1.0.6 — RESULTS

Fecha de verificación: 2026-11-17. Entorno: Python 3.12.3 del sistema.

## Estado por vía

- **catalog**: VERIFIED — Version 7 en vivo abre; 13 servidores, 11
  redes HTTP, 0 SSL, 0 errores de campo. Re-corrida en vivo byte por
  byte idéntica al `live.json` entregado.
- **files**: VERIFIED (asset) — el asset `pntvpn.json` abre (13
  servidores, 11 redes, 0 errores de campo); falta un `Config.json`
  real guardado por la app en un teléfono.
- **text**: NOT_APPLICABLE — sin esquema URI propio; solo
  vmess/vless/trojan/ss genéricos del fork de v2rayNG.
- **export**: PENDING — sin compartir por código en 1.0.6.

## Catálogo en vivo

API version 7, FileName `config.gen`, 13 servidores (10 gratuitos
Category 0 + 3 premium Category 2), 11 redes HTTP (9 con payload), 0
redes SSL. Asset: FileName `config.gen`, 13 servidores, 11 redes (10
con payload). Diferencias vivo vs asset: el vivo trae la red "T 10฿" y
los premium con V2ray; el asset trae en su lugar otra red, deja V2ray
vacío en los premium y `Limit=300` en los gratuitos (el vivo deja
`Limit` vacío).

## Self-tests del script operativo

- `MO_VPN.py --self-test`: 8/8 ok (round-trip XXTEA de catálogo y de
  campo, round-trip show/hide, campo vacío, asset `pntvpn.json` abre
  con FileName `config.gen` y 13 servidores, ServerIP y V2ray
  descifrados).
- `MO_VPN_archivos.py --self-test`: 9/9 ok (round-trip XXTEA, campo
  show/hide, campo vacío, asset abre con 13 servidores y 11 redes
  HTTP, ServerIP y V2ray descifrados, sin `tokenKey`, sin errores de
  campo).

## Re-corrida en vivo (byte por byte)

- `MO_VPN.py --url -o /tmp/live-mo-rerun.json`: **byte por byte
  idéntica** a `~/workspace/catalogs/movpn/live.json` (SHA-256
  `a49c822bada79a600f2ff0da48beda23a25a31c2833b6453f1b27ea10cef2496`).
  Tiempo de la descarga + descifrado: ~1,7 s (muy por debajo del tope
  de 20 s del worker y del presupuesto de 120 s de catálogo).

## Ruta supplied simulada en proceso

Simulación del camino `supplied_bridge.catalog()` sin red, con los
bytes guardados `work/config_live.gen` (SHA-256 `b433659d…`) y el
índice `work/api_live.json`:

- `api["fileUrl"]` coincide con la URL registrada `.../PNT_VPN/refs/heads/main/config.gen`: True.
- `decrypt_fields(decode(config_live.gen))` sin `tokenKey` **==**
  `live.json`: True (0,32 s).
- `MO_VPN_archivos.run(config_live.gen)` (camino C8 `run(bytes)->str`)
  **==** `live.json`: True (0,33 s).
- `MO_VPN_archivos.decode(pntvpn.json)`: 13 servidores, 11 redes HTTP,
  sin `tokenKey`, sin `_field_errors`.
- Entrada inválida (`run(b'not-base64!!!')`): devuelve `None`.

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
  self-tests y contra el asset real del APK y el cuerpo vivo guardado
  (hashes en MANIFEST.json).
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
