# WyrVPN 2.6.9 — RESULTS

Fecha de verificacion: 2026-11-15. Entorno: Python 3.12.3 del sistema y
venv con pycryptodome 4.4.0 + argon2-cffi 25.1.0
(`~/workspace/http-custom-update/venv/bin/python`).

## Estado por via

- **files**: VERIFIED — .wyr (texto wyrvpn:// + Base64 de sobre v01)
- **text**: VERIFIED — wyrvpn:// plano; WVE1 protegido solo sintetico (ver limitaciones)
- **catalog**: VERIFIED — sync POST, sobre v01, schema 21
- **export**: PENDING — sin endpoint de compartir por codigo en 2.6.9

## Catalogo en vivo

schema 21, 523 servidores (meta v7.5.0.3, 2026-11-14), 1.225 payloads (meta v2.4.3.0, 2026-11-13); 3 anuncios, 0 BLOCK_APP, 17 SETTING; 0 valores _func en el catalogo actual

## Self-tests del script operativo

WyrVPN.py --self-test 7/7 OK; WyrVPN_archivos.py --self-test 9/9 OK (2026-11-14, Python 3.12 del sistema y venv con cryptography).

## Tests del expediente

`python3 -m unittest discover -s tests -v` — ver salida en la entrega de
la Fase 1. Vectores SINTETICOS con claves de prueba (no reales): positivo
(round-trip), negativos (truncado, tag alterado, clave equivocada, Base64
invalido, HTML inesperado) y esquema del fixture. Los fixtures son
sinteticos (`tests/fixtures/synthetic_catalog.json`, hosts 203.0.113.0/24
y example.org); un fixture sintetico demuestra la logica implementada,
NO prueba compatibilidad con una version real ni conectividad remota.

## Que se probo con oraculo independiente

- AES-GCM/AES-CBC puros verificados contra pycryptodome (`cryptography`
  en WyrVPN) y contra vectores conocidos en los self-tests.
- Argon2id puro verificado contra argon2-cffi en los scripts operativos.
- Descargas en vivo verificadas dos veces o contra muestra guardada con
  hash (ver `MANIFEST.json`).

## Clasificacion de evidencia

- `VERIFIED`: descarga en vivo verificada o archivo real abierto.
- `VERIFIED_SYNTHETIC`: solo muestra sintetica sellada con el mismo metodo.
- `PARTIAL`: via que abre pero con valores que no descifran o pasos
  pendientes (ver limitaciones).
- `PENDING` / `REQUIRES_DEVICE`: falta muestra real de telefono o
  dispositivo registrado.
- `NOT_AUTHORIZED`: no aplica en este expediente (nada requirio sortear
  autenticacion ajena).

## Limitaciones

- WVE1 (contrasena/HWID) implementado segun ni1.java y verificado por round-trip contra la especificacion, pero SIN muestra real de la app: falta un .wyr protegido con contrasena y/o atado a dispositivo.
- El paso nativo para credenciales OVPN _func(...) esta bloqueado y no se reintenta; el catalogo actual tiene 0 valores _func.
- El servidor rechaza nonces reutilizados (HTTP 409) y a veces corta la respuesta chunked de ~1,7 MB a mitad con el cliente HTTP de Python (IncompleteRead); el script reintenta 3 veces con nonce nuevo y, si falla, se descarga con curl y se usa --raw.
- No hay intent-filter para el esquema wyrvpn:// en el manifest: es solo texto para pegar/compartir.
