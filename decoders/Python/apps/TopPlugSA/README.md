# TOP-PLUG-SA VPN 0.29.26 (mobi.ascensionrpg.khonavpn.activationtest) — archivos `.tpc`

Paquete `mobi.ascensionrpg.khonavpn.activationtest`, versión 0.29.26, build 89.
**Solo archivos: no se integra ningún catálogo multi-servidor ni esquema de
texto.** La app no tiene catálogo multi-servidor (sus 3 JSON públicos son
contacto, planes — solo precios — y avisos; el único perfil gratuito es el
sobre 50MB, que se sirve por un flujo de registro por dispositivo) y no
define esquema URI propio para importar perfiles.

## Origen

- `.apk` `TOP-PLUG-SA-v02926.apk` (26.502.337 B, SHA-256
  `fe3e03b1725fd489688abac1ddfc7200da83f94530db515d26b9e1906779c0b4`).
- Xray-core + JSch (SSH). Dossier de análisis local (no forma parte del
  repo): `~/workspace/catalogs/topplugsa/`.

## Método

Un archivo `.tpc` es texto con una cabecera que indica la variante; el
despachador es `decrypt_tpc()` en `topplugsa.py`:

| Variante | Formato | Estado |
|---|---|---|
| TOPPLUG4 (portable v4) | `TOPPLUG4\n<base64>`: nonce 12 B \|\| AES-256-GCM, clave = material de formato de 32 B del APK, AAD `TOPPLUG-PORTABLE-V4\n` | **VERIFIED_REAL** (muestra real del APK, tag GCM válido) |
| TOPPLUG5 (con contraseña v5) | `TOPPLUG5\n<base64>`: salt 16 B \|\| nonce 12 B \|\| AES-256-GCM, clave = PBKDF2-HMAC-SHA256 (600.000 iter, 256 bit), AAD `TOPPLUG-PASSWORD-V5\n`; el claro es un TOPPLUG4. Contraseña mínima 12 caracteres | Round-trip OK (falta muestra real) |
| TOPPLUG1 (firmado offline v2) | `TOPPLUG1\n<hex-firma>\n<JSON>`: firma ECDSA P-256 sobre `TOPPLUG-OFFLINE-V1\n` + JSON, perfil en claro | VERIFIED_SYNTHETIC |
| TOPPLUG2 (sellado v3) | `TOPPLUG2\n<hex-firma>\n<JSON>`: firma ECDSA P-256 sobre `TOPPLUG-SEALED-V3\n` + JSON | **Device-bound: NO se puede abrir** (ver abajo) |
| TOPPLUG-MANUAL-V2 | `TOPPLUG-MANUAL-V2\n<JSON>` en claro | VERIFIED_SYNTHETIC |

- La clave de formato de 32 B y las dos claves públicas P-256 (sobre 50MB
  e issuer `.tpc`) son constantes públicas de formato extraídas del APK.
  **No son credenciales de cuenta.** Sin ellas el formato no se puede abrir.
- Perfiles normalizados: `trojan` / `vless` / `ssh` (`ssh_mode`:
  direct_proxy, direct_tls, http_proxy, tls_proxy, tls_http_proxy;
  `network`: tcp / ws). Tope de entrada: 65.536 B.
- El módulo también descarga y verifica el sobre 50MB y los 3 JSON
  públicos (`fetch`, `50mb`); eso es herramienta de análisis, no parte
  de la ruta de archivos del worker.

## TOPPLUG2 es device-bound y NO se abre

El perfil de un TOPPLUG2 va cifrado con una `file_key` que llega en un
"grant" cifrado con la clave pública RSA-2048 del KeyStore del teléfono
dueño (`topplug_delivery_rsa_v1`, RSA-OAEP). Sin ese teléfono no se puede
descifrar. El decodificador verifica la firma ECDSA y devuelve solo
metadatos (`kind: "sealed-v3-device-bound"`, `profile: null`, con una nota
que lo explica). **TOPPLUG2 no se registra como abrible**: no hay
resultado parcial ni perfil inventado; el cliente debe mostrar que el
archivo pertenece a otro dispositivo.

## Uso

```bash
python topplugsa.py tpc perfil.tpc [--password CLAVE]
python topplugsa.py self-test
python topplugsa.py <archivo.tpc>   # modo directo del worker (stdin JSON)
python topplugsa.py fetch [--out catalog.json]
python topplugsa.py 50mb <sobre.json>
```

La API del worker es `decode(raw: bytes, password=None) -> dict` y
`run(data, password=None) -> str` (JSON del perfil o metadatos TOPPLUG2).
Un archivo no válido termina con código de error con `code`
(`PASSWORD_REQUIRED`, `INVALID_CREDENTIALS`, `AUTH_FAILED`,
`DECODE_FAILED`); una contraseña incorrecta y datos alterados son
indistinguibles (el tag GCM no verifica en ambos casos).

## Integración (solo archivos)

- Motor Cloud: entrada `"tpc"` en `_C8_FILE_ENGINES`
  (`cloud/workers/python/engine.py`) → `decoders/Python/apps/TopPlugSA/topplugsa.py`.
  La ruta suministrada (`FILE_ROUTES`, derivada de
  `supplied-integrations.json`) apunta al mismo módulo. `"tpc"` se añade
  a la lista de formatos con contraseña permitida en `decode_file`
  (junto a `xveon`/`xvn`): la contraseña llega por stdin como JSON,
  nunca por argv, entorno o logs.
- Inventario público generado: `cloud/web/content/file-formats.json`
  (`offlineSupported: false`, `cloudSupported: true`,
  `credentialFields: ["password"]`, por TOPPLUG5).
- Inventario suministrado: `cloud/web/content/supplied-integrations.json`,
  id `top-plug-sa`, `catalogState: FILE_ONLY`, `requests: []`, sin tarjeta
  en `cloud/web/lib/server-vpn-catalog.mjs` (patrón XU Tunnel / XVEON).
- Icono original exacto: `cloud/web/public/server-vpn-icons/top-plug-sa.png`
  (PNG 192×192, 4387 bytes, SHA-256
  `cfcd74545d6ca3f3821c41fc82715afe457667ff6b0a228f46fb65e883c7a850`,
  sin redibujar).
- No se toca nada bajo `android/` ni `decoders.json`, `switches.json`,
  `C0_FORMAT_MATRIX.csv`. Sin cambios en `text-formats.json` (no hay
  esquema de texto), sin broker, sin `catalog_vpn_bridge.py`, sin
  entrada en la allowlist de catálogos de `engine.py`.
- `CATALOG_VERSION` no se toca en este cambio (el coordinador lo sube
  una vez para todo el lote).
- PyCryptodome es dependencia de runtime del decodificador
  (AES-GCM, PBKDF2, ECDSA): el Python del worker debe importarla con
  `HOME` sobrescrito (mismo requisito que los demás decodificadores
  que la usan).

## Evidencia y límites

- TOPPLUG4 es VERIFIED_REAL: la muestra `assets/activation-helper.tpc`
  del APK descifra con tag GCM válido. **La muestra NO está en el repo**
  (lleva credenciales); el self-test la busca como fixture opcional y
  salta si no está.
- TOPPLUG5: round-trip con rechazo de contraseña incorrecta; falta una
  muestra real exportada por la app con su contraseña.
- TOPPLUG1 y TOPPLUG-MANUAL-V2: sintéticos (vectores firmados/construidos
  en el self-test); falta una muestra real.
- TOPPLUG2: firma verificable, perfil imposible sin el teléfono dueño.
- El catálogo vivo (3 JSON públicos) NO se integra como proveedor: son
  contacto/precios/avisos, no un catálogo multi-servidor. El perfil
  gratuito 50MB solo se actualiza por registro de dispositivo.
- Pruebas: [TESTING.md](TESTING.md).
