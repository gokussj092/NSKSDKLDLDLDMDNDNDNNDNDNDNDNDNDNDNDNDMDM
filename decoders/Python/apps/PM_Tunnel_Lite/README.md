# PM Tunnel Lite — 1.0 (10)

Paquete `com.pmtunnel.app`; proveedor fijo `pm-tunnel-lite`, integrado en la nube
siguiendo el patrón 7NET/GCP/NetFlux (broker HTTPS fijo, worker aislado, contrato de
documento completo, control administrativo individual). Python >=3.10 y
`pycryptodome==3.23.0`. **Codec propio standalone**: NO reutiliza `../../renz.py`
ni registra ningún perfil nuevo en él — la estructura y el delta XXTEA
(`0x7a56d3e1`) coinciden con la ruta RENZ, pero el material de claves
(`PASSWORD`, `FIXED_SALT`, `IV`) es distinto de todas las entradas de
`RENZ_KEYS` (p. ej. `gcpvpn`), así que el perfil compartido no abre este
catálogo; y registrar un perfil nuevo está prohibido (rompería el generador
Android de 16 sufijos RENZ / 239 formatos). No se toca nada bajo `android/` —
una actualización de catálogo, archivos o textos en el servidor no debe tocar
la APK. PM Tunnel Lite queda solo online, sin puerto offline. No necesita APK,
SO, Android ni cuenta en runtime.

## Métodos confirmados

| Entrada | Descifrado (codec propio, modos del `RenzUtils.decrypt` nativo) | Salida |
| --- | --- | --- |
| Catálogo, sobre exterior | Base64 → AES-128-CBC, SHA-256(sal)[:16] e IV fijo → XXTEA de delta propio → restar 2 a cada byte | JSON con `Version`, `Servers`, `Networks` |
| Campos `Name`/`Subname`/puertos/`flag`/`CloudfrontDNS`/`ServerHTTP`/`Obfs`/`CustomCert`, `Name`/`Info`/`TLSVersion`/`DNSServerHost`/`DNSResolver`, `ProxySettings`, `SlowDNS.NSNameServer`/`PubKey`, `V2Ray.UUID`, `UDPOptions` | Modo 0 | Nombres, puertos, DNS, claves SlowDNS, opciones UDP |
| Campos `ServerIPHost`, `SNIHost`, `Payload`, `V2Ray.V2RayHost`/`PATH`, `V2Ray.SNIHost`/`CustomV2RAYConfig` | Modo 1: HKDF-SHA256 → Threefish-256 (tweak = índice de bloque, 0) → AES-128-CBC | Hosts, SNI, payloads, V2Ray |
| Campos `Username`/`Password` (por servidor y de nivel superior) | Modo 2: PBKDF2-HMAC-SHA256 (100 000 iters) → XXTEA → AES-256-CBC | Usuarios y contraseñas |
| Archivos `.js` y `custom_payload.json` | Modo 0 (mismo sobre que el catálogo) | Catálogo o lista de servidores |
| Enlaces `pmtunnellite://` | Modo 0 (JSON de UN servidor) | Servidor con campos descifrados |
| Recurso `res/ae/drlb` | Modo 3 (HKDF-32 + AES-256-CBC) → DEX v037 anti-tamper | **NO es formato de usuario; no se integra como tal** |

La tabla de modos de las secciones anidadas (`SlowDNS`, `V2Ray`, `UDPOptions`)
se estableció como la corrección SlowDNS de GCP: cada campo abre con exactamente
un modo a texto plausible y falla con los otros dos, verificado en TODAS las
instancias vivas (52/52). Los campos que no abren con su modo documentado se
sirven como están, sin inventar esquema ni valores. Las claves desconocidas se
conservan tal cual; nada se descarta (el descifrador del dossier descartaba
`SlowDNS`/`V2Ray`/`UDPOptions` — este módulo las conserva y descifra).

**Estos formatos no autentican criptográficamente el ciphertext.**
Padding, longitud y estructura validan el formato, no su autenticidad.
Si falla el sobre exterior o faltan `Servers`/`Networks`, el lector
rechaza el catálogo completo. HMAC de autenticación de conexión:
`NOT_OBSERVED` (ver dossier).

## Fuentes comprobadas

Única URL del updater de este build:

`https://raw.githubusercontent.com/rajon-apps-2026/PM-Tunnel-Lite-Updater/refs/heads/main/update.js`

Lectura pública autorizada, re-verificada el 2026-11-22 ~16:10 Tijuana:
**HTTP 200, 140224 bytes, SHA-256 `d09b5d73…82d`, Version 159, 10 servidores
y 151 redes** — bytes idénticos a la descarga de las 04:10 del mismo día.
915/915 campos no vacíos descifran (modo 0: 694, modo 1: 155, modo 2: 14;
anidados: 52); 0 sin descifrar. 6/10 servidores traen usuario/contraseña;
2 usan certificado propio. No existe flag libre/premium en el catálogo
(`Protocol` es categoría de transporte, no libre/premium). CLI HTTPS real,
CLI stdin y worker aislado entregan el mismo documento completo con fixtures
sintéticos; el catálogo en vivo se descifra en ~1–2 s por el mismo codec
(límite del worker de catálogos: 120 s). No se guardan en Git catálogos reales,
valores descifrados ni credenciales.

Se preservan orden, metadatos, listas, valores vacíos, nulos y tipos
desconocidos. Los JSON internos permanecen como texto exacto. No se
eligen hosts, sustituyen marcadores ni inician conexiones VPN.

## Uso

```bash
python server_catalog_decoder.py --download
python server_catalog_decoder.py copia-catalogo.txt
python server_catalog_decoder.py --stdin < copia-catalogo.txt
python file_decoder.py perfil.js
python file_decoder.py custom_payload.json
```

Los dos lectores exponen `run(data: bytes) -> str`, y `file_decoder`
además `decode_text("pmtunnellite://...") -> str | None`. No se aportó una
exportación real independiente; las rutas `.js` y `pmtunnellite://` se
comprueban con fixtures sintéticos (round-trip verificado en el dossier;
ver [pruebas](TESTING.md)). No se certifica un roundtrip de exportador
Android.

## El sufijo `.js` no se registra como formato de archivo

Decisión documentada en `status.md` §2: `.js` es una extensión genérica;
el catálogo de formatos despacha solo por sufijo (regla
`longest-filename-suffix`, sin detección por contenido) y el motor
despacha solo por sufijo (predicados de contenido solo para cinco
sufijos compartidos), así que registrar `js` haría que TODO archivo
`.js` intentara descifrarse como PM Tunnel Lite. El módulo implementa
la decodificación `.js` (uso directo y CLI); las rutas integradas son
el catálogo en vivo y `pmtunnellite://` (esquema inequívoco; el sufijo
de texto `pmtunnel` no necesita ser sufijo de archivo — hay 18
precedentes en `text-formats.json`).

## Cloud

- Bridge privado, worker aislado, contrato de documento completo y
  control administrativo individual. Una URL HTTPS fija, DNS IPv4
  público validado, TLS y ninguna redirección; el cliente no puede
  elegir destinos. La descarga del worker es un GET plano sin headers,
  exactamente como la app (Volley GET plano); el `agent` del broker
  (`"PM Tunnel Lite"`) sigue el patrón RENZ (`"GCP VPN"`,
  `"NetFlux VPN"`) y el resultado no depende de él (curl y urllib
  plano devuelven los mismos bytes).
- PNG original exacto del icono launcher del XAPK: **512×512, 295765
  bytes**, SHA-256 `cd38af8b…3218d`.
- Catálogo mínimo **95**; conserva switches y versión persistente.
  La entrega deja código en el árbol, sin push ni despliegue.
- Dossier y pruebas: `analysis/com.pmtunnel.app/10/`
  (`ANALYSIS.md`, `RESULTS.md`, `DEPENDENCIES.md`,
  `dependencies.lock.json`) y [pruebas](TESTING.md).
  Entregables previos (fuera del repo): `~/workspace/catalogs/pmtunnel/`
  (`pmtunnel.py`, `pmtunnel_files.py`, `NOTES.md`).
