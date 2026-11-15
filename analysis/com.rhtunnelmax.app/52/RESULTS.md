# RH Tunnel Lite 39.0.1 — RESULTS

Fecha de verificacion: 2026-11-15. Entorno: Python 3.12.3 del sistema y
venv con pycryptodome 4.4.0 + argon2-cffi 25.1.0
(`~/workspace/http-custom-update/venv/bin/python`).

## Estado por via

- **files**: VERIFIED_SYNTHETIC — .hs: sin .hs real exportado; el sintetico (enlace SabDev://) abre; el asset sabconfig.hs real abre
- **text**: VERIFIED — SabDev:// (servidor, 17 campos) y shanS:// (red, 23 campos), round-trip con registros reales
- **catalog**: VERIFIED — blob doble-AES, Version 200.38 en vivo
- **export**: PENDING — el metodo save() de .hs no tiene llamadas visibles en 39.0.1; envoltorio exacto de exportacion sin confirmar

## Catalogo en vivo

Version 200.38, 17 servidores (7 paises segun FLAG; OpenVPN 8, V2Ray 7, DNSTT 2), 200 redes/payloads (ovpn 172, v2ray 14, udp 13, dnstt 1; cf 126, ws 69, http 5); 134 redes con payload. Asset integrado: Version 200.8, 17 servidores, 181 redes.

## Self-tests del script operativo

RH_Tunnel_Lite.py --self-test 9/9 OK (incluye descarga en vivo v200.38); RH_Tunnel_Lite_archivos.py --self-test 6/6 OK (2026-11-14). AES puro sin pycryptodome: mismo sabconfig.hs abre con salida byte-identica.

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

- Falta un .hs REAL exportado por la app para confirmar el envoltorio exacto de exportacion (save() sin llamadas visibles en 39.0.1; el .hs sintetico contiene un enlace SabDev://).
- Falta un archivo real protegido (servidor/red con usuario/clave propios del usuario).
- Si la descarga devuelve 401, el desarrollador roto el token: hay que extraer el nuevo de la APK actualizada.
- No se probo en un telefono real con la app instalada.
- COLISION DE SUFIJO .hs: el sufijo .hs lo comparte JK VPN (com.fastvpn.jk), con un formato distinto (Tink Streaming AEAD). NO resuelto en este expediente: la decision del discriminador esta pendiente en la fase de discriminadores del parche. Este expediente documenta solo el formato RH.
