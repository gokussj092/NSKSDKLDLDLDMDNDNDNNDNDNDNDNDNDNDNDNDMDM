# HexVPN 1.7.3-Rev — análisis (app propia, FILE_ONLY)

**App:** HexVPN 1.7.3-Rev, versionCode 73, paquete `com.hex.tunnel.jotchuast`.
**Archivo analizado:** `HexVPN_1.7.3-Rev_0_btjx.apks`, 36.767.965 B,
SHA-256 `df5c64a9cfde6a84908d3928c32a539a458a708f92550e9bc6736d7b3790d735`
(base + splits `arm64_v8a` / `es` / `xhdpi`). El APK no se guarda en el repo.

> Nota del propietario (2026-11-17): HexVPN NO es lo mismo que Hex Tunnel:
> se revisó como app propia. Resultado: mismo paquete, misma versión y mismo
> código que el build que originó el decodificador `.hexcm` del repo.
> El método de archivo se comparte POR IDENTIDAD de hashes, no por asumir
> el nombre.

## Resultado

| Cosa | Estado |
|---|---|
| Archivos `.hexcm` | **ABREN** (simple y doble; ver abajo) |
| Catálogo en vivo | **NO_CATALOG** — sin endpoint recuperable por análisis estático |
| Servidores / redes / payloads en vivo | 0 / 0 / 0 |
| Esquema URI propio de texto | **No existe** |
| Formato HXS3 (Hex Custom) | **No aplica** a este build |

## Identidad del build

- `lib/arm64-v8a/libkovsec.so` SHA-256
  `5353b4967322798501cbc07eef62692576059a4badfc835a2de865f2054ca74c`
  = pin `SO_SHA256` de `scripts/apk_analysis/hex_tunnel_recover.py`.
- `lib/arm64-v8a/libhexvpn.so` SHA-256
  `1823e85250a6f9041fbce5a10ce7924fa5f4f222483b4ff7e583734d47b156b3`
  = pin `HEX_SHA256` del mismo script.
- `assets/protection/manifest.json`: `build_id`
  `kovsec-aab-ddce2868d8949b10`; los 3 `kovsec-*.bin` coinciden en
  tamaño y SHA-256 con el manifiesto.
- Los 3 paquetes KovSec descifran con AEAD válido (ChaCha20-Poly1305,
  clave derivada de `libkovsec.so`, AAD `KXPKG1` + FNV-1a del build_id).
- El decodificador del repo (`decoders/Python/apps/Hex_Tunnel/file_decoder.py`,
  SHA-256 `9bb9958199b3e3695ffc8a0003621837a95dbee3f5b10f0d086fd0539d265e68`)
  es byte-idéntico al `HexVPN_archivos.py` entregado en este lote.
  Se hizo sobre este mismo build protegido: 6 archivos reales abrieron
  completos (26 campos de servidor, firma válida, contraste íntegro con JCA)
  y 12 documentos válidos sintéticos (simples y dobles) + 10 rechazos
  verificados (`tests/test_hex_tunnel.py`, `tests/golden/hexcm_vectors.json`).

## Archivos `.hexcm` (formato de ESTE build)

Exterior Base64 de `salt[16] || nonce[12] || ciphertext || tag[16]`:

```
clave = PBKDF2-HMAC-SHA256(password, salt, 100_000 iter, 32 B)
plano = AES-256-GCM(clave, nonce, ct, tag)
```

- Si el plano empieza por `{`: documento JSON firmado (variante simple).
- Si no: el plano es Base64 de
  `nonce[12] || ChaCha20-Poly1305(ct) || tag[16]` con clave fija
  `INNER_KEY` (variante doble, `CustomServerShare.doubleDecrypt`).
- Firma: SHA-256 del JSON sin la propiedad raíz `signature` (conservando
  lexemas y orden del exportador) concatenado con la constante de la app.
  Documento exigido: `version: 1`, `server` no vacío, `meta.blocked`
  booleano, firma de 64 hex válida.

Verificación en este trabajo: round-trip sintético simple y doble con
las primitivas del propio lector, tag alterado rechazado, documento vacío
rechazado (`test_hexvpn.py` en el lote; `tests/test_hex_tunnel.py` en el repo).
**Pendiente:** un `.hexcm` real exportado por ESTE build en un teléfono
reconfirmaría el camino de extremo a extremo; la variante doble solo tiene
verificación sintética (el repo tampoco dispone de una exportación real doble).

El manifest declara `VIEW` con `pathPattern .*\.hex` (content/file,
`*/*`) y un segundo filtro `application/octet-stream` sin patrón.
`.hexcm` entra por el segundo filtro. No hay muestra `.hex` ni método
confirmado para `.hex`: pendiente un archivo `.hex` real si existe.

## Catálogo: NO_CATALOG (cadena de evidencia)

1. **Las URLs viven en métodos cifrados con KovSec.** `AppConfig`
   expone `updatesJsonUrl()`, `serversUpdateUrl()`, `serversKey()`,
   `speedTestDownloadUrl/PingUrl/UploadUrl`, `hex_push()`,
   `hex_seever_updates()`, `telegram*Url`, `soporte()` — TODOS con
   `code: None` en el DEX. Igual `ServerUpdateManager.checkForUpdates /
   checkForUpdatesSync / evaluate / applyUpdate`, `ServerCatalogStore
   (.getServers/.setServers/.refresh/.ensureInitialized)`,
   `ServerPresence.fetchCounts/sendPresence/buildClient` y
   `HexMessagingService.onMessageReceived`. En `classes.dex` el 74% de
   los métodos de la app no tiene código en el DEX (3.454/4.636) y en
   `classes3.dex` el 57% (1.595/2.776): KovSec los sirve cifrados en
   `assets/protection/kovsec-{000,001,002}.bin`.
2. **Los paquetes descifran pero son bytecode de VM propia.**
   AEAD verificado (ver arriba), pero la sección de código no es
   Dalvik ni contiene strings legibles, y el pool de strings de
   `libkovsec.so` solo trae nombres/firmas de métodos (ni una URL).
   Revertir el ISA de `libkovsecvm.so` queda fuera de este trabajo.
3. **No hay SDK de Firebase Database/Auth/Firestore en el APK.**
   Solo Firebase Messaging, Installations y Analytics. El
   `firebase_database_url` de recursos
   (`https://hex-tunnel-afd6e-default-rtdb.firebaseio.com`,
   proyecto `hex-tunnel-afd6e`) es configuración vestigial de
   `google-services`: la app no tiene con qué leer RTDB.
4. **El RTDB no es público.** `HexVPN.py --probe` hizo GET anónimo a
   la raíz y a 26 nodos candidatos (`servers`, `free_servers`,
   `vip_servers`, `free`, `vip`, `config`, `updates`, `version`,
   `app_config`, `server_list`, `servers_list`, `public`, `catalog`,
   `data`, `settings`, `info`, `status`, `freeServers`, `vipServers`,
   `all_servers`, `serverlist`, `hexvpn`, `hex`, `tunnel`,
   `announcements`, `notices`): **27/27 HTTP 401 `Permission denied`**
   (ver `live.json`, re-sondeado 2026-11-17 22:54 UTC). Sin autenticación
   no hay lectura.
5. **Nada en recursos, assets ni librerías nativas.** Sin URL de
   actualizaciones en `resources.arsc`, sin JSON de servidores en
   `assets` (solo flags, geoip/geosite, dexopt y KovSec), sin URL en
   ninguna de las 16 librerías de `split_config.arm64_v8a.apk`.
6. **Lo que SÍ existe:** `ServerCatalogStore` (caché local de la
   lista), `ServerPresence` (heartbeat + conteos por OkHttp),
   `ServerUpdateNotifier` / `ServerUpdateJobService` /
   `ServerUpdateReceiver` / `ServerUpdateAlarm` (avisos periódicos) y
   `HexMessagingService` (FCM; tema `hex_seever_updates`). Las
   actualizaciones llegan probablemente por FCM o por el JSON de
   `updatesJsonUrl` vía OkHttp — ambas rutas necesitan el teléfono
   (token FCM) o la URL cifrada.

`live.json` registra el fallo con evidencia (27 sondas 401, 0
servidores). No contiene servidores inventados ni APIs de descarga.

## Texto / enlaces

- **Sin esquema URI propio:** el manifest no declara `hexvpn://` ni
  similar. No se incluye ningún esquema.
- `V2RayLinkImporter` importa por pegado enlaces estándar
  `vless://`, `vmess://`, `trojan://`, `ss://`, `socks://`,
  `hysteria2://` y WireGuard — son los enlaces genéricos que SP-DECODE
  ya soporta; no hay nada propio de HexVPN que registrar.

## Librerías nativas

`libhexvpn.so` aquí es DISTINTO del de Hex Custom 10.6.4
(367.592 B, con `nativeOpen`/`nativeSeal` y HXS3): este no tiene
`HXS3` ni `nativeOpen`/`nativeSeal`; por eso el formato `.hexcm` de
este build es el Base64/PBKDF2/AES-GCM(+ChaCha) y no HXS3.

## Integración en el repo (esta entrega)

- El decodificador NO se reescribió ni duplicó: ya estaba en
  `decoders/Python/apps/Hex_Tunnel/file_decoder.py`, byte-idéntico.
- Entrada supplied nueva `hex-tunnel` (FILE_ONLY, `requests: []`) en
  `cloud/web/content/supplied-integrations.json`, siguiendo la forma de
  las entradas FILE_ONLY existentes (`str-vip-proxy`, `fx-tunnel`,
  `hex-custom`). **Sin `catalogModule`**: Hex_Tunnel no tiene script de
  catálogo (`serverCatalogDecoder` es `null` en su manifest) y ningún
  código del repo exige ese campo para una entrada FILE_ONLY
  (`supplied-integrations.mjs` no lo referencia; `supplied_bridge.load`
  solo se invoca con `catalogModule` para proveedores con catálogo, y
  `hexcm` está excluido de `FILE_ROUTES` por discriminación de contenido
  en `engine.py`).
- Icono `cloud/web/public/server-vpn-icons/hexvpn.png` (512×512,
  SHA-256 `26c75e7b0f2e878aa0d41c8cc6e6128f4badfd047c991def617f17785a31db71`).
- `CATALOG_VERSION` 87 → 88; supplied 81 → 82 (pin en
  `cloud/web/lib/supplied-integrations.mjs` y
  `cloud/web/tests/supplied-integrations.test.mjs`).

## Auditoría HMAC

- Archivo: integridad local por tag AES-256-GCM + firma SHA-256 del
  documento (ver arriba). No es autenticación de conexión VPN.
- Transporte / autenticación de conexión: NO_OBSERVED en este dossier;
  no se investigó el handshake del túnel.
