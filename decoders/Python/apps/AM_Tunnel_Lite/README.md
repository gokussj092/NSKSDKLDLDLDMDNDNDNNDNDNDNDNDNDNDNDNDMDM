# AM Tunnel Lite — AM (63)

Paquete `app.vpn.amtunnellite`; proveedor fijo `am-tunnel-lite`, integrado en la nube
siguiendo el patrón 7NET/GCP/NetFlux (broker HTTPS fijo, worker aislado, contrato de
documento completo, control administrativo individual). Python >=3.10, **solo
stdlib** (sin `pycryptodome`, sin dependencias de terceros). **Codec propio
standalone**: NO reutiliza `../../renz.py` ni registra ningún perfil nuevo en él —
el XXTEA usa la clave estática `'...|...'` y el delta **no estándar `0x9E5729B1`**
(literal `-1638454863` de `Ltm.b`); con el delta estándar `0x9E3779B9` el catálogo
no abre. No se toca nada bajo `android/` — una actualización de catálogo o
archivos en el servidor no debe tocar la APK. AM Tunnel Lite queda solo online,
sin puerto offline. No necesita APK, SO, Android ni cuenta en runtime.

## Métodos confirmados

| Entrada | Descifrado (codec propio) | Salida |
| --- | --- | --- |
| Catálogo remoto, sobre exterior | Base64 (quitar `' '` y `'\n'`) → XXTEA (clave `'...|...'`, delta `0x9E5729B1`) → JSON UTF-8 | JSON con `Version`, `Free_servers`, `Payloads` |
| Archivo `pdrv2.json` local | Mismo sobre exterior que el remoto | Catálogo completo |
| Assets `wg/am*.conf` (1.000 embebidos) | Sin cifrado: `Endpoint` / `Hash1` / `Hash2` (Base64 → 32 B) | Endpoint IPv4 + 2 hashes |

La estructura por servidor: `server_name`, `server_host` (endpoints separados por
`;`), `server_port` / `server_udp_port` / `ssl_port` / `username` / `password` /
`custom_cert` (vacíos en las 172 entradas), `category`. Por payload:
`friendly_name`, `payload` (plantilla), `host`=`Pulled`, `port`=`Pulled`,
`method`=`http`, `query`=`normal`, `sslws`=`false`, `category`.

**Estos formatos no autentican criptográficamente el ciphertext.**
Padding, longitud y estructura validan el formato, no su autenticidad.
Si falla el sobre exterior o faltan `Version` / `Free_servers` / `Payloads`, el
lector rechaza el catálogo completo. HMAC de autenticación de conexión:
`NOT_OBSERVED` (ver dossier).

## Fuentes comprobadas

Única URL del updater de este build:

`https://freedomnavigate.com/updater/8112011e98856d3ca814d0f8ce3231`

Lectura pública autorizada, re-verificada el 2026-11-22: **HTTP 200, 163960 bytes
Base64, SHA-256 `38cca537…49da`, Version 4.6, 172 servidores libres (3.341
endpoints) y 137 payloads, 0 premium / 0 VIP / 0 privados** — bytes idénticos en
dos descargas independientes el mismo día. Catálogo embebido `assets/pdrv2.json`:
**Version 1.5, 165 servidores, 128 payloads** (SHA-256
`3afd30a1…3c688d3`), abre con el mismo esquema y clave. CLI HTTPS real, CLI stdin
y worker aislado entregan el mismo documento completo con fixtures sintéticos.
No se guardan en Git catálogos reales, valores descifrados ni credenciales.

Se preservan orden, metadatos, listas, valores vacíos, nulos y tipos
desconocidos. No se eligen hosts, sustituyen marcadores ni inician conexiones VPN.

## Descarga por rangos (reserva de tiempo — leer antes de desplegar)

El servidor corta cada respuesta a múltiplos de 16 KiB (cierra la conexión, a
veces con 0 bytes leídos): **un GET plano NO descarga el catálogo completo**
(verificado en vivo: un GET sin `Range` se corta a 98.304–114.688 bytes y la
respuesta se aborta). Por eso la descarga se hace por rangos de 16 KiB con
reanudación y reintentos, tanto en el worker/CLI (`server_catalog_decoder.py`,
`codec.fetch_catalog`) como en el broker (`server-vpn-provider.mjs`,
`downloadAmTunnelLite`, que usa `pinnedRequest` con `Range` y acepta 206).
El broker además envía la UA Android exacta del script (sin ella, 403).

**Reserva:** tiempo observado 11–18 s vía proxy de la VM (reintentos incluidos),
cerca del tope de 20 s del worker de archivos — pero el catálogo usa el worker
de catálogos (límite 120 s) y el broker tiene su propio plazo de 30 s, así que
la descarga cabe en ambos. **No se sube ningún tope.** Si el endpoint deja de
aceptar `Range` o la UA Android, la descarga falla con error explícito en vez
de entregar un catálogo truncado (el worker rechaza el XXTEA incompleto).

## Sin importación por el usuario, sin esquema de texto

Verificado en el APK y el DEX: no hay intent-filter de importación de archivos,
ni selector, ni esquema URL propio, ni `.sks`. `udp://*` son opciones de DNS en
la UI, no enlaces de importación. Por tanto:

- **Archivo:** solo `pdrv2.json` (copia local del catálogo, sufijo `pdtv2`
  registrado en `file-formats.json` y `_C8_FILE_ENGINES`). Los `.conf` de
  WireGuard son assets internos del APK: se parsean con `file_decoder.py --wg`
  (uso directo/CLI), sin sufijo registrado.
- **Texto:** sin esquema propio; nada se registra en `text-formats.json` ni en
  `text_bridge.py`.

## Uso

```bash
python server_catalog_decoder.py --download
python server_catalog_decoder.py copia-catalogo.bin
python server_catalog_decoder.py --stdin < copia-catalogo.bin
python file_decoder.py pdrv2.json
python file_decoder.py --wg am0001.conf --json
```

Los dos lectores exponen `run(data: bytes) -> str`. No se aportó una exportación
`pdrv2.json` real independiente del teléfono de Pedro; la ruta se comprueba con
el `pdrv2.json` embebido real (Version 1.5) y con fixtures sintéticos (round-trip
verificado en el dossier; ver [pruebas](TESTING.md)). No se certifica un
roundtrip de exportador Android.

## Cloud

- Bridge privado, worker aislado, contrato de documento completo y
  control administrativo individual. Una URL HTTPS fija, DNS IPv4
  público validado, TLS y ninguna redirección; el cliente no puede
  elegir destinos. La descarga del broker es un GET por rangos con la UA
  Android exacta del script (ver la sección de rangos arriba); el worker
  es offline y solo descifra los bytes que le entrega el broker.
- PNG original exacto del icono del APK (`res/drawable/ic_app_icon.png`):
  **479×440, 30105 bytes**, SHA-256 `ad8aab86…2d7a`. No existe un icono
  512×512 en el APK; no se redibujó ni reescaló.
- Catálogo mínimo **96**; conserva switches y versión persistente.
  La entrega deja código en el árbol, sin push ni despliegue.
- Dossier y pruebas: `analysis/app.vpn.amtunnellite/63/`
  (`ANALYSIS.md`, `RESULTS.md`, `REPRODUCE.md`, `MANIFEST.json`,
  `DEPENDENCIES.md`, `dependencies.lock.json`) y [pruebas](TESTING.md).
  Entregables previos (fuera del repo): `~/workspace/catalogs/amtunnel/`
  (`amtunnel.py`, `amtunnel_files.py`, `NOTES.md`).

## Nota sobre la ficha antigua `am-tunnel-lite-vpn`

El catálogo ya tenía una tarjeta `am-tunnel-lite-vpn` (`remote:null`,
desactivada) de cuando el lector aún no se había recuperado. El proveedor
nuevo es `am-tunnel-lite` (id distinto, con broker y worker propios); la
tarjeta antigua **no se toca en esta entrega** y queda pendiente de decidir
con Pedro si se retira. Su test (`server-vpn-catalog.test.mjs`, "AM retains
its original PNG while protected catalog support is pending") sigue
vigente para esa ficha.
