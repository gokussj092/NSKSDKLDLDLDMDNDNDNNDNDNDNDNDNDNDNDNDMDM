# GCP VPN — 1.1 (11)

Paquete `com.gcpvpn.net`; proveedor fijo `gcp-vpn`, integrado en la nube
siguiendo el patrón 7NET (broker HTTPS fijo, worker aislado, contrato de
documento completo, control administrativo individual).
Python >=3.10 y `pycryptodome==3.23.0`. Reutiliza las primitivas y la ruta
de archivos de `../../renz.py`; no necesita APK, SO, Android ni cuenta
en runtime.

## Métodos confirmados

| Entrada | Descifrado (ruta RENZ genérica, perfil `gcpvpn`) | Salida |
| --- | --- | --- |
| Catálogo, sobre exterior | Base64 → AES-128-CBC, SHA-256(seed)[:16] e IV fijo → XXTEA de delta propio → restar 2 a cada byte | JSON con `Version`, `Servers`, `Networks` |
| Campos `*host*`/`*path*` | Threefish-256 con HKDF-SHA256 y tweak `(índice, índice*64)` → AES-128-CBC | Hosts, SNI, payloads |
| Campos `*username*`/`*password*` y claves cortas de credencial | PBKDF2-XXTEA-AES | Usuarios y contraseñas por servidor |
| Resto de campos | Modo principal, con fallback a speciale | Nombres, puertos, banderas, DNS, V2Ray, SlowDNS |
| Archivos `.gcpvpn` y `gcpvpn://` | Ruta RENZ canónica | Perfil exportado |

No se escribió un codec propio por campo como el de 7NET: no hay
evidencia del APK para una tabla de modos propia de GCP, y la ruta
genérica ya descifra 2.736 campos del catálogo en vivo. Los 51 campos
cortos de presentación que no abren con ningún modo del repo
(`Servers[].Name`/`Subname`, `Networks[].Info`) se sirven como están,
sin inventar esquema ni valores.

**Estos formatos no autentican criptográficamente el ciphertext.**
Padding, longitud y estructura validan el formato, no su autenticidad.
Si falla el sobre exterior o faltan `Servers`/`Networks`, el lector
rechaza el catálogo completo. HMAC de autenticación de conexión:
`NOT_OBSERVED` (ver dossier).

## Fuentes comprobadas

Única URL del updater de este build:

`https://raw.githubusercontent.com/kiranoble/config/refs/heads/main/gcpvpn2026`

Lectura pública autorizada del 2026-11-19: **HTTP 200, 505176 bytes,
SHA-256 `fff27a6d…8044e`, Version 3304, 90 servidores y 334 redes**.
El sobre abre con las claves actuales de `renz.py` (sin rotación);
81/90 servidores traen credenciales que descifran con el modo
sensible. CLI HTTPS real, CLI stdin y worker aislado entregan el
mismo documento completo con fixtures sintéticos; el catálogo en vivo
se descifra en ~1–2 s por el mismo codec (límite del worker de
catálogos: 120 s). No se guardan en Git catálogos reales, valores
descifrados ni credenciales.

Se preservan orden, metadatos, listas, valores vacíos, nulos y tipos
desconocidos. Los JSON internos permanecen como texto exacto. No se
eligen hosts, sustituyen marcadores ni inician conexiones VPN.

## Uso

```bash
python server_catalog_decoder.py --download
python server_catalog_decoder.py copia-catalogo.txt
python server_catalog_decoder.py --stdin < copia-catalogo.txt
python file_decoder.py perfil.gcpvpn
```

Los dos lectores exponen `run(data: bytes) -> str`. No se aportó una
exportación real independiente; las rutas `.gcpvpn` y `gcpvpn://` se
comprueban con fixtures sintéticos (10/10 archivo, 8/8 texto por la
ruta real del worker). No se certifica un roundtrip de exportador
Android.

## Cloud

- Bridge privado, worker aislado, contrato de documento completo y
  control administrativo individual. Una URL HTTPS fija, DNS IPv4
  público validado, TLS y ninguna redirección; el cliente no puede
  elegir destinos.
- PNG original exacto `com.gcpvpn.net.apk:res/i/ca.png` (icono
  launcher verificado con androguard): **240×240, 2863 bytes**.
- Catálogo mínimo **92**; conserva switches y versión persistente.
  La entrega deja código en el árbol, sin push ni despliegue.
- Dossier y pruebas: `~/workspace/catalogs/gcpvpn/dossier-fragments/`
  (`VERIFY_DECODERS.md`, `LIVE_CATALOG.md`, `INTEGRATION_CLOUD.md`)
  y [pruebas](TESTING.md).
