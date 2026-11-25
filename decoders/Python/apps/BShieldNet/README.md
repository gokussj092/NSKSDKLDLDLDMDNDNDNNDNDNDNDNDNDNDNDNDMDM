# B SHIELD NET — 2.9 (29)

Paquete `xyz.bshieldnet.org`, base v2rayNG (`renz.javacodez.v2ray`) +
RENZ (`renz.javacodez.vpn`); proveedor fijo `bshield-net`,
integrado en la nube siguiendo el patrón GCP/NetFlux (broker HTTPS
fijo, worker aislado, contrato de documento completo, control
administrativo individual). Python >=3.10, `pycryptodome>=3.18.0`.
No necesita APK, SO, Android ni cuenta en runtime.

## Métodos confirmados

| Entrada | Descifrado | Salida |
| --- | --- | --- |
| Catálogo vivo (`GET` plano a GitHub raw) | Sobre exterior RENZ perfil `bshield` + pase interior recursivo (modos 0/1/2/3) | JSON completo con `Version`, `Servers` (90), `Networks` (792), `Username`, `Password`, `Notes` |
| Archivos `.bshield` | Perfil `bshield` (ruta RENZ canónica) | JSON con `application`, `extension`, `config` |
| Texto `bshieldnet://` / `bshield://` | Perfil `bshield` (ruta RENZ canónica) | JSON con `application`, `protocol`, `config` |

**El perfil `bshield` YA estaba en el repo** (`decoders/Python/renz.py`:
semilla, IV, sal, URL del catálogo, sufijo `.bshield`, esquemas
`bshieldnet://` / `bshield://`), `.bshield` ya estaba en
`file-formats.json` y en la matriz C0, y el perfil ya estaba en la
tabla Android. Esta entrega NO registra nada de eso de nuevo: solo
añade el **catálogo vivo como proveedor** (`bshield-net`) y las dos
entradas de texto en `text-formats.json` (que faltaban). El
`bshieldnet.py` de esta carpeta es el script entregable original,
con una sola adaptación: la búsqueda de `renz.py` ahora prueba
también el layout del repo (`decoders/Python/`, `parents[2]`); el
algoritmo no cambia.

El sobre exterior es Base64 → AES-128-CBC (clave =
SHA-256(KEY_SEED)[:16], IV fijo, PKCS7) → XXTEA custom (delta
0x7A56D3E1, 6 + 52/n rondas) → restar 2 por byte → JSON. El
generador inverso está verificado: re-cifrar el plaintext vivo
reproduce el blob original byte a byte. Matiz del motor RENZ
compartido (no de este script): el pase interior recursivo NO es
idempotente — re-cifrar un catálogo YA descifrado y volver a
descifrarlo cambia 156 hojas; no afecta al uso real. HMAC de
autenticación de conexión: `NOT_OBSERVED` (ver dossier).

## Fuentes comprobadas

Única URL del catálogo de este build:

`https://raw.githubusercontent.com/snapb/B-SHIELD-NET-2026/refs/heads/main/b_shield_net_2026`

Lectura pública autorizada del 2026-11-24: **HTTP 200, 911,897
bytes, SHA-256 `17975a39…`, Version 7.34, 90 servidores, 792
networks**; dos descargas seguidas con el mismo blob y el mismo
descifrado. El catálogo completo lleva credenciales de servidor
(usuario, contraseña, host, UUID V2Ray, certificados): **NO va a
Git, ni al ZIP, ni a Drive** — solo como adjunto del chat
(precedente Ways Tunnel). El vector dorado de esta entrega es
sintético (valores ficticios `test.invalid`). No se guardan en Git
catálogos reales, valores descifrados, sesiones ni credenciales.
El JSON de resultado solo lleva los datos del catálogo
descifrado; la URL de descarga NO va en el JSON de resultado.

## Uso

```bash
python server_catalog_decoder.py --download
python server_catalog_decoder.py copia-catalogo.b64
python server_catalog_decoder.py --stdin < copia-catalogo.b64
python bshieldnet.py --fetch [--redacted]
python bshieldnet.py perfil.bshield
python bshieldnet.py --text 'bshieldnet://...'
python bshieldnet.py --self-test
```

Los lectores de catálogo exponen `run(data: bytes) -> str`;
`bshieldnet.py` expone `run` / `run_text` / `fetch_catalog` /
`redact_catalog`. Sin créditos dentro del script ni del resultado.

## Cloud

- Bridge privado, worker aislado, contrato de documento completo y
  control administrativo individual. Una URL HTTPS fija en
  `raw.githubusercontent.com` (443, sin puerto no estándar, sin
  redirecciones); el cliente no puede elegir destinos. La ruta
  genérica del broker la sirve (mismo patrón que GCP/NetFlux); no
  hace falta descargador dedicado.
- Icono launcher del XAPK 2.9, redimensionado Lanczos 240×240 →
  192×192 (**44,744 bytes**, SHA-256
  `d5c58895…`; ver `manifest.json`).
- Catálogo mínimo **99** (lo fija el coordinador al fusionar,
  98 → 99); este staging NO sube `CATALOG_VERSION`.
- Dossier y pruebas: `analysis/xyz.bshieldnet.org/29/` y
  [pruebas](TESTING.md).
