# Bee VPN 1.10.11.2 — RESULTS

Fecha de verificacion: 2026-11-15. Entorno: Python 3.12.3 del sistema y
venv con pycryptodome 4.4.0 + argon2-cffi 25.1.0
(`~/workspace/http-custom-update/venv/bin/python`).

## Estado por via

- **files**: VERIFIED_SYNTHETIC — .bee: muestra sintetica sellada con el metodo real; falta uno REAL exportado
- **text**: VERIFIED_SYNTHETIC — sin esquema URI propio; solo v2rayng://install-config/install-sub genericos
- **catalog**: PARTIAL — Version 5.72 en vivo abre; 2 sobres de campo no abren con ninguna clave del APK (ver limitaciones)
- **export**: PENDING — sin compartir por codigo, registro de dispositivo ni creditos en 1.10.11.2

## Catalogo en vivo

Version 5.72, 55 servidores, 668 redes. Sobres de campo en vivo: 4.419 unicos, 4.417 abren, 2 no. Asset: Version 1.01, 67 servidores, 657 redes; sobres de campo 1.237 unicos, 1.228 abren, 9 no.

## Self-tests del script operativo

Bee_VPN.py --self-test (venv, via rapida): asset FIELD 1.01 67/657, field_sample 36/36, 0 fallos. Bee_VPN_archivos.py --self-test: asset FIELD 1.01 67/657; round-trip FILE con marcadora OK; round-trip FIELD sin marcadora OK. Ambos scripts compilan (py_compile).

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

- 2 sobres de campo en vivo (BugDNS y CustomProxy de redes de Kazajistan 611-620) no abren con ninguna clave ni variante de este APK; 9 iguales en el asset. El script los deja codificados tal cual y los reporta.
- Descifrar los 4.419 sobres tarda ~100 s con --workers 4 (~2 min con el reintento parcial; en serie ~20 min) y ~15-20 s por sobre en stdlib puro: por encima del tope de 20 s del worker de nube; hace falta la via rapida argon2-cffi o subir el tope.
- Falta un .bee REAL exportado por la app en un telefono.
- COLISION DE SUFIJO .bee: el sufijo .bee ya pertenece al metodo historico BEE TUNNEL (decoders/Python/ultra.py). NO resuelto en este expediente: la decision esta pendiente en la fase de discriminadores del parche. Este expediente documenta solo el formato Bee VPN 1.10.11.2.
