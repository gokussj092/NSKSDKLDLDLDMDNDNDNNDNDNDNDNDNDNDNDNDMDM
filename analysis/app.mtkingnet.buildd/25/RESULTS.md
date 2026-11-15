# MT KING NET 15.35.2 — RESULTS

Fecha de verificacion: 2026-11-15. Entorno: Python 3.12.3 del sistema y
venv con pycryptodome 4.4.0 + argon2-cffi 25.1.0
(`~/workspace/http-custom-update/venv/bin/python`).

## Estado por via

- **files**: VERIFIED_SYNTHETIC — cached_cloud_bundle.json: sin muestra REAL de telefono; la muestra local (respuesta en vivo) abre; assets del APK abren
- **text**: VERIFIED_SYNTHETIC — sin esquema propio; enlaces V2Ray estandar ya cubiertos por SP-DECODE
- **catalog**: VERIFIED — worker ISVSoft con firma App-Proof, Version 21.31.299 en vivo
- **export**: PENDING — cloud share sin verificar en vivo (necesita dispositivo registrado y creditos)

## Catalogo en vivo

Version 21.31.299, 80 servidores (80 online), 367 tweaks (127 con payload HTTP, 211 con SNI), settings con predefinedCredentials (ssh, openvpn, v2ray, hysteria, shadowsocks, wireguard) y 1 certProfile. type=servers devuelve los mismos 80 servidores sin tweaks/settings. Assets del APK: v1.0.0, 9 servidores, 11 tweaks.

## Self-tests del script operativo

MT_King_Net.py --self-test 10/10 OK (3 vectores enc: reales, 2 firmas HMAC, 3 round-trip, 1 tag alterado, 1 mini-catalogo); MT_King_Net_archivos.py --self-test 8/8 OK. Catalogo completo en vivo ~5 s (1.103 valores enc:, dentro del tope de 20 s del worker).

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

- Falta un cached_cloud_bundle.json REAL de un telefono (la estructura es la misma por codigo, pero no hay muestra real).
- El flujo cloud share (subir/descargar + registro de dispositivo + creditos) NO esta verificado en vivo: necesita un dispositivo registrado.
- Falta un enlace real pegado en la app para confirmar el parseo del nucleo v2rayNG con sus servidores.
- La app no tiene esquema URI propio ni deep link (solo MAIN/LAUNCHER); la importacion de enlaces es por pegado.
