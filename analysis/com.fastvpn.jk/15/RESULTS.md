# JK VPN 1.5 — RESULTS

Fecha de verificacion: 2026-11-15. Entorno: Python 3.12.3 del sistema y
venv con pycryptodome 4.4.0 + argon2-cffi 25.1.0
(`~/workspace/http-custom-update/venv/bin/python`).

## Estado por via

- **files**: VERIFIED — .hs: el catalogo .hs descargado de la misma URL que usa la app abre; falta un .hs exportado por un usuario real para comparar
- **text**: VERIFIED_SYNTHETIC — sin esquema URI propio; enlaces v2ray estandar (9 vless:// descifrados en el catalogo)
- **catalog**: VERIFIED — .hs Tink Streaming AEAD, Version 1.114 en vivo, 174 valores ED: descifrados
- **export**: PENDING — profile.enc local usa Keystore del dispositivo y NO es descifrable fuera del telefono

## Catalogo en vivo

Version 1.114, 39 servidores (OpenVPN 20, V2Ray 9, Tun2Socks 5, Hysteria 5), 21 redes (Websocket 8, Websocket(Cloudfront) 9, V2Ray 3, Hysteria 1), setOpenVPN vacio; 174 valores ED: descifrados (0 restantes); 61 segmentos GCM, todos los tags validos.

## Self-tests del script operativo

JK_VPN_catalogo.py --self-test 13/13 OK (Python del sistema, backend GCM puro) y 14/14 OK (venv con pycryptodome). JK_VPN_archivos.py --self-test 12/12 OK en ambos interpretes (round-trip .hs, multi-segmento 9.360 B, enlaces, ovpn 60).

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

- No hay archivo .hs exportado por un usuario real para comparar (la muestra es la descarga de la misma URL que usa la app).
- profile.enc no es descifrable sin el dispositivo (Keystore).
- El campo setOpenVPN viene vacio en el catalogo actual.
- No se probo la importacion en la app real (sin telefono con JK VPN).
- COLISION DE SUFIJO .hs: el sufijo .hs lo comparte RH Tunnel Lite (com.rhtunnelmax.app), con un formato distinto (doble AES + empaquetado chino). NO resuelto en este expediente: la decision del discriminador esta pendiente en la fase de discriminadores del parche. Este expediente documenta solo el formato JK VPN 1.5.
