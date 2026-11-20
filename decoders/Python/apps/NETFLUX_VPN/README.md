# NetFlux VPN — 1.1 (11)

Paquete `app.netfluxvpn.net`; proveedor fijo `netflux-vpn`, integrado en la nube
siguiendo el patrón 7NET/GCP (broker HTTPS fijo, worker aislado, contrato de
documento completo, control administrativo individual). App SEPARADA de GCP VPN:
proveedor propio, sin fusión, aunque comparta método RENZ y catálogo.
Python >=3.10 y `pycryptodome==3.23.0`. Reutiliza las primitivas de
`../../renz.py` con despacho EXPLÍCITO al perfil existente `gcpvpn`
(mismo material de claves, mismo catálogo en vivo que GCP VPN); NO se
registra ningún perfil `netflux` nuevo en `renz.py` ni se toca nada
bajo `android/` — una actualización de catálogo, archivos o textos en
el servidor no debe tocar la APK. Si los blobs de NetFlux y GCP
divergen algún día, eso sería un cambio a decidir aparte. NetFlux
queda solo online, sin puerto offline, igual que GCP VPN. No necesita
APK, SO, Android ni cuenta en runtime.

## Métodos confirmados

| Entrada | Descifrado (ruta RENZ genérica, perfil `gcpvpn`, despacho explícito) | Salida |
| --- | --- | --- |
| Catálogo, sobre exterior | Base64 → AES-128-CBC, SHA-256(seed)[:16] e IV fijo → XXTEA de delta propio → restar 2 a cada byte | JSON con `Version`, `Servers`, `Networks` |
| Campos `*host*`/`*path*` | Threefish-256 con HKDF-SHA256 y tweak `(índice, índice*64)` → AES-128-CBC | Hosts, SNI, payloads |
| Campos `*username*`/`*password*` y claves cortas de credencial | PBKDF2-XXTEA-AES | Usuarios y contraseñas por servidor |
| Resto de campos | Modo principal, con fallback a speciale | Nombres, puertos, banderas, DNS, V2Ray, SlowDNS |
| Archivos `.netflux` y `netfluxvpn://` | Despacho explícito al perfil `gcpvpn` en `file_decoder.py` (enlaces, además, por bloque explícito en `text_bridge.py`); la ruta canónica de `renz.py` NO los sirve porque no hay registro `netflux` | Perfil exportado |

No se escribió un codec propio por campo como el de 7NET: no hay
evidencia del APK para una tabla de modos propia de NetFlux, y la ruta
genérica ya descifra 2.736 campos del catálogo en vivo (mismo blob que GCP VPN). Los 51 campos
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

`https://raw.githubusercontent.com/kiranoble/config/refs/heads/main/netflux`

Lectura pública autorizada del 2026-11-20: **HTTP 200, 505176 bytes,
SHA-256 `fff27a6d…8044e`, Version 3304, 90 servidores y 334 redes** —
blob byte a byte idéntico al de `gcpvpn2026`.
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
python file_decoder.py perfil.netflux
```

Los dos lectores exponen `run(data: bytes) -> str`. No se aportó una
exportación real independiente; las rutas `.netflux` y `netfluxvpn://` se
comprueban con fixtures sintéticos (round-trip 7/7 archivo y 7/7 texto
con `netflux.py`, más la ruta explícita a `gcpvpn` en
`tests/test_netfluxvpn.py`).
No se certifica un roundtrip de exportador Android.

## Cloud

- Bridge privado, worker aislado, contrato de documento completo y
  control administrativo individual. Una URL HTTPS fija, DNS IPv4
  público validado, TLS y ninguna redirección; el cliente no puede
  elegir destinos.
- PNG original exacto `app.netfluxvpn.net.apk:res/h/cd.png` (icono
  launcher verificado con androguard): **240×240, 51006 bytes**.
- Catálogo mínimo **94**; conserva switches y versión persistente.
  La entrega deja código en el árbol, sin push ni despliegue.
- Dossier y pruebas: `analysis/app.netfluxvpn.net/11/`
  (`ANALYSIS.md`, `RESULTS.md`, `CLOUD_EVALUATION.md`) y [pruebas](TESTING.md).
  Entregables previos (fuera del repo): `~/workspace/catalogs/netfluxvpn/`
  (`netflux.py`, `tests/test_netflux_file_text.py`, `NOTES.md`).
