# MO VPN 1.0.6 — ANALYSIS

Fecha de verificación: 2026-11-17. Paquete `com.movpn.vpnth`,
versionCode 6, versionName 1.0.6, minSdk 23, targetSdk 36. APK: XAPK de
APKPure (37.551.062 B, SHA-256
`31397a90de90a32597e6e87dff9133c0cff913d0ae5a17a9c1d97f34ba90e92b`,
igual al publicado por APKPure). Base 15.590.333 B. Ficha de Play leída
el mismo día: MoVPN, TH-VPN Internet, 50K+ descargas, actualizada
24 oct 2026. Sin trabajo previo en tandas 1–15.

## Plantilla PNT — misma, pero OTRA app y OTRA ruta

Misma plantilla que PNT VPN: mismas librerías nativas, mismo asset
`pntvpn.json`, mismo repo GitHub (`sansoe2022/PNT_VPN`), pero con su
propia clave de catálogo y sus propios archivos `api.json` /
`config.gen`. El `pnt-vpn` del repo (`com.pntvpn.net`,
`sansoe2022/new_pntvpn`) NO cubre esta app. No confundirlas.

Librerías nativas (todas en `config.arm64_v8a.apk`; la base no tiene
`.so`): `libgojni.so` (30.558.672, núcleo Go/v2ray), `libovpnudp.so`,
`libdns.so`, `libovpncli.so`, `libmmkv.so`, `libtun2socks.so`,
`libh1.so`, `libpdnsd.so`, `libnative-sec.so` (37.352, claves y URL de
la API por JNI). No hay `libputils.so`.

## Método exacto del catálogo

### Descarga (2 etapas, GET planos sin auth)

- **Etapa 1 — índice:** la app lo pide con Volley `JsonObjectRequest`
  GET, sin cabeceras propias, a la URL de `NativeSec.getApiUrl()`:
  `GET https://raw.githubusercontent.com/sansoe2022/PNT_VPN/refs/heads/main/api.json`
  → JSON `{"version": 7, "message": ..., "fileUrl": "<url del
  catálogo>", "messageWarning": ..., "title": ..., "link": <Play
  Store>, "website": <Play Store>, "versionCode": 6}`. Si la versión
  guardada es menor que `version`, descarga el catálogo.
- **Etapa 2 — catálogo:** la app lo descarga con PRDownloader, GET
  plano sin auth, a `<filesDir>/SVPN/Config.json`; si no existe, lee el
  asset `assets/pntvpn.json`:
  `GET https://raw.githubusercontent.com/sansoe2022/PNT_VPN/refs/heads/main/config.gen`
  → cuerpo: una línea Base64 estándar → Base64 → **XXTEA** (clase
  `SVPNDex`, DELTA fijo `-772015605` = `0xD1FBFA0B`, clave =
  `NativeSec.getAesKey()` = `com.movpn.paidapk`) → JSON con `FileName`,
  `tokenKey`, `userName`, `repoName`, `InterUnit`, `RewardUnit`,
  `premiumKey`, `BannerUnit`, `OpenAppUnit`, `WebUrl`, `ContactUrl`,
  `FacebookUrl`, `TelegramUrl`, `BgUrl`, `Servers`, `HTTPNetworks`,
  `SSLNetworks`, `Ovpn_Cert` (plantilla OpenVPN en texto plano).
- El script envía `User-Agent: Dalvik/2.1.0 (Linux; U; Android 14;
  Redmi 14C Build/UP1A.231005.007)`; GitHub raw responde igual con
  cualquier UA. Sin autenticación, token de sesión, firma ni parámetros.

### Valores nativos (recuperados emulando los JNI con Unicorn)

`libnative-sec.so` (arm64) expone los JNI sin ofuscar:
`Java_com_movpn_vpnth_core_NativeSec_getApiUrl` @0x2ac4,
`getAuthHash` @0x3c3c, `getAesKey` @0x4d34, `getDelta` @0x5f30.
Emulación con el mismo arnés que PNT VPN (`work/emu_native.py`,
adaptado a estos offsets); el `.so` también guarda dos cadenas hex de
64 caracteres en `.rodata` que `getDelta` usa para una comprobación
anti-manipulación, no necesarias para decodificar.

| Función | Valor |
|---|---|
| `getApiUrl()` | la URL de `api.json` de arriba |
| `getAesKey()` | `com.movpn.paidapk` (clave XXTEA del catálogo) |
| `getAuthHash()` | `5741` (clave XXTEA de los campos) |
| `getDelta()` | `0x3B2959AF` (DELTA de `XxTea`) |

### Campos cifrados de cada servidor/red (`FileUtils.showJson`)

```
Base64 -> XXTEA (clase XxTea, DELTA = NativeSec.getDelta() = 0x3B2959AF,
                 clave = FileUtils.getPass() = "5741")
       -> texto UTF-8 con caracteres portadores (U+2C00-U+2DFF)
       -> cada caracter -= 5741, dos veces (De2.decryptString x2)
       -> texto plano
```

Campos: `ServerIP`, `ServerCloudFront`, `ServerHTTP`, `V2ray`,
`SlowIP`, `PublicKey`, `Username`, `Password`, `NetworkPayload`,
`SquidProxy`, `WSHost`, `Address`, `NetworkFrontQuery`,
`NetworkBackQuery`.

### SEGURIDAD — tokenKey excluido

El catálogo trae un campo `tokenKey` de 40 caracteres que es un token
de GitHub. NO se incluye en `live.json`, NO lo imprime ningún script,
NO se reproduce en este expediente ni en el resumen: `MO_VPN.py` lo
elimina antes de escribir `-o` y `MO_VPN_archivos.py` lo elimina en
`decode()`. El valor nunca se escribió en ningún entregable.

### Contador en línea — NO verificado desde esta VM

El campo `Info` de cada servidor es `http://<host>/server/online_app`
(puerto 80). Los hosts `m.free*.mvpn5g.com` resuelven por DNS pero la
conexión TCP falla desde esta VM (HTTP 000 en los 3 probados, puertos
80 y 81). No es un fallo del catálogo: el `--online` del script lo
intenta y registra `None`. Queda pendiente comprobarlo desde una red
donde esos hosts respondan.

## Archivos guardados (Config.json / pntvpn.json)

- **No hay formato propio de archivo de perfil.** El manifiesto
  declara 15 actividades y **ningún intent-filter** (sin `ACTION_VIEW`,
  sin esquemas, sin sufijos de archivo). No hay referencias a `.sks`,
  `.movpn` ni a ningún otro sufijo en el manifiesto, en las 172.554
  cadenas DEX ni en el bytecode. No se construyó ningún decodificador
  `.sks`.
- El único "archivo" de la app es el catálogo guardado:
  `<filesDir>/SVPN/Config.json` (cuerpo cifrado tal cual lo descarga
  PRDownloader) o el asset `pntvpn.json`. `MO_VPN_archivos.py` los
  descifra con el mismo método y devuelve el JSON completo sin
  `tokenKey`. Verificado: el asset abre (13 servidores, 11 redes, 0
  errores de campo) y el cuerpo vivo guardado `work/config_live.gen`
  también.

## Esquemas de texto/enlaces — ninguno propio

- **Manifiesto:** ningún intent-filter con esquema propio.
- **`vmess://` / `vless://` / `trojan://` / `ss://`:** solo aparecen
  como literales del fork de v2rayNG (importación estándar por
  portapapeles); no son esquemas propios de MO VPN ni hay un
  `MO_VPN_textos.py`. No se construyó decodificador de enlaces propio.

## Resultado en vivo (2026-11-17, re-corrido el mismo día)

| Fuente | API version | FileName | Servidores | HTTP | SSL |
|---|---|---|---|---|---|
| `assets/pntvpn.json` del APK | — | config.gen | 13 (10 libres + 3 premium) | 11 (10 con payload) | 0 |
| GET oficial (`--url`) | **7** | **config.gen** | **13 (10 libres + 3 premium)** | **11 (9 con payload)** | **0** |

- Servidores en vivo: 10 gratuitos Category 0 (Thailand) + 3 premium
  Category 2 (Singapore). SSH 22, SSL 443, proxy 8080; cada uno con
  enlace `vless://` por WebSocket y credenciales SSH propias.
- Redes HTTP en vivo: 11, 9 con payload (tipos `cf`/`http`/`ws`).
- **Cero errores de campo**: todos los valores cifrados abrieron
  (`_field_errors` ausente en vivo y en el asset).
- Re-corrida en vivo byte por byte idéntica al `live.json` entregado
  (ver RESULTS.md).
- Dato tal cual viene: "Server Free 010" duplica host y UUID de "Server
  Free 005"; no es error del script.
- `Ovpn_Cert` y el campo `ovpnCertificate` por servidor son la plantilla
  OpenVPN en texto plano (certificado y clave de cliente compartidos por
  la app, incluidos tal cual en `live.json` como parte de los datos del
  catálogo).

## Auditoría HMAC (obligatoria, AGENTS.md §2.2)

- **Integridad de archivos/catálogos:** NOT_OBSERVED — el formato no
  tiene MAC ni HMAC; la integridad se valida solo por estructura (JSON
  válido, `FileName` `config.gen`, listas presentes). XXTEA sin
  autenticación: un cuerpo alterado puede descifrar a basura y se
  rechaza por JSON inválido, no por tag.
- **Derivación criptográfica:** NOT_OBSERVED — sin HMAC en la
  derivación; las claves son constantes fijas de formato recuperadas de
  `libnative-sec.so` (`com.movpn.paidapk`, `5741`) con deltas fijos.
- **Transporte VPN:** NOT_OBSERVED — no se revisó el transporte VPN.
- **Autenticación de conexión:** NOT_OBSERVED — no se observó HMAC de
  autenticación de conexión. La mera presencia de XXTEA no demuestra
  autenticación.

## Integración al repo (ruta y advertencias)

- **Ruta recomendada: supplied-only, como su gemela `pnt-vpn`.**
  El broker supplied ya sabe hacer la descarga en 2 etapas y validar
  que el `fileUrl` del índice coincide con la URL registrada (patrón
  PNT en `supplied_bridge.py` `catalog()`). La tarjeta se genera sola
  desde la entrada supplied (`SUPPLIED_CATALOG_ITEMS`).
- **Por qué NO C8 directo para el catálogo:** `MO_VPN.py` expone
  `decode()` + `decrypt_fields()`, pero su `run()` es la CLI (devuelve
  `int`), NO un `run(bytes) -> str`; el bridge C8 exige `module.run(payload)`.
  Además el broker C8 es de URL única por proveedor y no puede expresar
  la descarga en 2 etapas con validación del `fileUrl`. Un registro
  dual (supplied + C8) es incoherente aquí: el broker supplied
  empaquetaría las 2 fuentes en un bundle
  `spdecode-supplied-catalog-v1` que un módulo C8 no sabría abrir.
- **Rama necesaria en `supplied_bridge.py` `decode_one()`** (el camino
  genérico `module.decode(...)` devolvería los campos todavía cifrados;
  hay que aplicar `decrypt_fields`, igual que la rama PNT):
  `if app == "MO_VPN": result = module.decrypt_fields(result)`.
  Ver spec exacta en el REPORT de entrega.
- **`MO_VPN_archivos.py` como `fileModule`:** expone `decode()` y
  `run(bytes) -> str`; el camino genérico de `file_decode()` lo cubre
  sin rama nueva. `extensions: []`, `textPrefixes: []`: sin entradas en
  `file-formats.json`, `text-formats.json` ni `_C8_FILE_ENGINES`.
- **Icono:** `mo-vpn.png` 512×512 en `cloud/web/public/server-vpn-icons/`
  y `MO_VPN.png` en el directorio del proveedor (mismo SHA-256).
  Nota: el APK **no trae icono raster** (su icono es el vector
  `res/drawable/ic_icon.xml`); el PNG es el icono de Play servido por
  APKPure a 512×512. El asset `assets/networks/icon_logo.png` (510×510)
  es el logo "P" de la plantilla PNT, NO es el icono de MO VPN y no se
  usó.
- **CATALOG_VERSION:** no se toca en este staging (86 en el head
  `5df9fc50`); +1 una sola vez para toda la entrega cuando se aplique el
  parche.

## Estado

- **catalog:** VERIFIED — descarga en vivo verificada, re-corrida byte
  por byte idéntica.
- **files:** VERIFIED (asset) — falta un `Config.json` real de teléfono.
- **text:** NOT_APPLICABLE — sin esquema propio.
- **export:** PENDING — sin compartir por código en 1.0.6.
