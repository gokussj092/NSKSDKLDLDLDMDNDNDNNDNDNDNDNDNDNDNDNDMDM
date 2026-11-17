# Click Tunnel 1.0 — RESULTS

Fecha de verificación: 2026-11-17. Entorno: Python 3.12.3 del sistema
y venv con pycryptodome 4.4.0.

## Estado por vía

- **catalog**: VERIFIED — v5.1.8 en vivo abre; 0 valores sin descifrar.
  OJO: `decode()`/`run()` devuelven el documento CON `DefUpdateURL` y
  `updater`; el puente supplied debe quitar ambas claves (ver abajo).
- **files**: VERIFIED_SYNTHETIC — `.sup`/`.wsuiou`: self-test 8/8;
  falta un archivo REAL exportado.
- **text**: PENDING — `xfsd://` sin clave real; no es esquema URI, no
  se registra.
- **export**: PENDING — sin clave `xfsd://` real.

## Catálogo en vivo (re-corrida 2026-11-17 ~20:58 Tijuana)

Descarga con el script entregado contra el endpoint real:

- `--url --summary`: `Version 5.1.8, Servers 7, Tweaks 18` (0,86 s).
- `--url -o /tmp/click_full.json` (17.432 B): **byte por byte idéntico**
  al `live.json` entregado (SHA-256
  `9bb6f8e5991203ea82220c919ddce59d7f4872687aee0e90f002184007ecd8c8`).
- `run()` offline sobre la respuesta guardada
  (`work/live_response.txt`, 29.932 B, SHA-256
  `02ad2fa1b2f4633481080a67a19a5eb5bc6de5d198d276a7d16e6c57ce9edfdc`):
  0,09 s; devuelve el documento CON `DefUpdateURL`/`updater`
  (17.570 B); quitando esas dos claves es idéntico al `live.json`
  entregado (parseado). `run()` con entrada inválida devuelve `None`.
- `live.json` entregado: sin `DefUpdateURL`, sin `updater`, sin
  `raw.githubusercontent`, sin `github` en todo el texto.

## Self-tests del script operativo

- `Click_Tunnel_archivos.py --self-test`: **8/8 perfiles** (tipos 0/1/2,
  6 DNS, 7 UDP, 5 y 9 v2ray, 8 WireGuard, con contraseña, caducidad,
  DeviceID, mensaje y Server; caso borde unicode/emoji correcto).
  `field_counts`: [31, 27, 27, 27, 27, 27, 31, 27].
- `py_compile` de ambos scripts: OK (sistema y copias del staging).
- `run(b"not base64!!!")`, `run(b"garbage")`, `run(b"")` (ambos
  scripts): `None`.

## Tests del expediente

`~/workspace/http-custom-update/venv/bin/python -m unittest discover -s tests -v`
— ver salida en la entrega. Fixture: copia del asset incrustado
`res/raw/noobdev.js` (v1.0.0, 1 servidor, 1 tweak; campos cifrados).
Un fixture de asset demuestra la lógica implementada con material real
del APK, NO prueba conectividad remota. La conectividad real la prueba
la re-corrida en vivo byte por byte de arriba.

## Qué se probó con oráculo independiente

- XXTEA modificado + AES-CFB/CBC verificados contra el código
  descompilado de la app (jadx 1.5.3; tabla de cadenas `Cp0.j`
  portada y verificada en vectores conocidos en `work/cp0.py`).
- Descargas en vivo verificadas dos veces (entrega original + re-corrida
  de esta tarea) con comparación byte por byte.

## Clasificación de evidencia

- `VERIFIED`: descarga en vivo verificada o archivo real abierto.
- `VERIFIED_SYNTHETIC`: solo muestra sintética sellada con el mismo método.
- `PARTIAL`: vía que abre pero con valores que no descifran o pasos pendientes.
- `PENDING` / `REQUIRES_DEVICE`: falta muestra real de teléfono o
  dispositivo registrado.
- `NOT_AUTHORIZED`: no aplica en este expediente (nada requirió sortear
  autenticación ajena).
