# VLX Tunnel VPN VLX v14 — RESULTS

Fecha de verificacion: 2026-11-15. Entorno: Python 3.12.3 del sistema y
venv con pycryptodome 4.4.0 + argon2-cffi 25.1.0
(`~/workspace/http-custom-update/venv/bin/python`).

## Estado por via

- **files**: VERIFIED_SYNTHETIC — .vlx: muestra sintetica sellada con el metodo real; falta uno REAL exportado
- **text**: VERIFIED_SYNTHETIC — sin esquema URI propio; solo v2rayng://install-config/install-sub y enlaces estandar
- **catalog**: VERIFIED — GET estatico con User-Agent obligatorio, sobre Argon2id + AES-256-GCM sin marcadora, Version 23.759 en vivo
- **export**: PENDING — sin compartir por codigo, registro de dispositivo ni creditos en VLX v14

## Catalogo en vivo

Version 23.759, 19 servidores (todos con host no vacio), 721 redes; campos protegidos 4.518/4.518 descifrados (via rapida). Asset: Version 1.01, 1 servidor, 1 red, 17/17 campos.

## Self-tests del script operativo

VLX_Tunnel_VPN.py --self-test: asset FIELD 1.01 1/1, round-trip clave en vivo sin marcadora OK; con venv field_sample 17/17. VLX_Tunnel_VPN_archivos.py --self-test (venv): round-trip con ambas claves OK, field_in_profile OK. En vivo --url --workers 4: 23.759, 19/721, campos 4.518/4.518.

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

- Falta un .vlx REAL exportado por la app en un telefono.
- El servidor exige el User-Agent exacto de la app (con otro UA responde 404).
