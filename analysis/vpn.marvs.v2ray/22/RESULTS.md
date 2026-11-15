# RH Tunnel Secure (Marvs V2Ray) RHV1 — RESULTS

Fecha de verificacion: 2026-11-15. Entorno: Python 3.12.3 del sistema y
venv con pycryptodome 4.4.0 + argon2-cffi 25.1.0
(`~/workspace/http-custom-update/venv/bin/python`).

## Estado por via

- **files**: VERIFIED_SYNTHETIC — .bbtun: muestra sintetica sellada con el metodo real; falta uno REAL exportado
- **text**: VERIFIED_SYNTHETIC — sin esquema propio; solo v2rayng://install-config/install-sub estandar
- **catalog**: VERIFIED — GET estatico, sobre Argon2id + AES-256-GCM con letra marcadora, Version 2.74 en vivo
- **export**: PENDING — sin compartir por codigo ni registro de dispositivo en RHV1

## Catalogo en vivo

Version 2.74, 23 servidores, 211 redes; campos protegidos 1.496/1.496 descifrados (via rapida); 50 valores que no abren son textos Info en claro, no sobres. Asset incluido: Version 1.24, 10 servidores, 32 redes, 314/314 campos.

## Self-tests del script operativo

Marvs_V2Ray.py --self-test: asset FIELD 1.24 10/32, round-trip clave en vivo con marcadora OK; con venv (argon2-cffi + PyCryptodome) field_sample 48/48. Marvs_V2Ray_archivos.py --self-test: round-trip con ambas claves OK. En vivo --url: 2.74, 23/211, campos 1.496/1.496, 0 fallos.

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

- Falta un .bbtun REAL exportado por la app en un telefono para confirmar el decodificador de archivos de extremo a extremo (hoy solo muestra sintetica sellada con el mismo metodo).
- Los iconos de red se descargan de una ruta de iconos del mismo dominio (no forma parte del catalogo).
- En Play y APKPure figura como RH Tunnel Secure (antes Marvs V2Ray).
