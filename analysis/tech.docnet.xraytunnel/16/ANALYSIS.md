# ANALYSIS — V2Ray Injector 1.4.2 (`tech.docnet.xraytunnel`, code 16)

- **App:** V2Ray Injector ("v2ray injector", V2K) 1.4.2 (versionCode 16)
- **APK analizado:** `v2ray_injector_1.4.2_6_2722.apks` (82,042,520 bytes),
  SHA-256
  `ab40c88887f48bc5ed094f12537919d569cbda0fccbaac3a8798a123bdf34de1`
- **Fecha:** 2026-11-28
- **Alcance:** catálogo en vivo + archivos `.v2k` + Xray JSON + enlaces
  de texto. Sin push, sin despliegue desde este trabajo.
- **Veredicto: EL CATÁLOGO ABRE EN VIVO (1,233 servidores, 63 configs).
  Los archivos `.v2k` y los enlaces son VERIFIED_SYNTHETIC**
  (round-trip con el formato propio de la app; falta un `.v2k` real
  exportado).

> V2Ray Injector es un cliente Xray-core. Su catálogo vive en un
> Cloudflare Worker y usa un único sobre AES-256-GCM; el mismo sobre
> protege los assets incluidos, la caché en disco y los archivos
> `.v2k` cifrados. Tras abrir el sobre no queda nada cifrado: no hay
> cifrado por campo.

## 1. Catálogo en vivo — VERIFIED_REAL

- **Observación:** `SecureConfigFetcher.kt` replica exactamente:
  `GET https://xraytunnel-config.admin6795.workers.dev/api/config`
  con `Accept: application/json`, `User-Agent: XrayTunnel/1.0` y
  `X-API-KEY` (clave del worker). Sin body. 3 intentos, pausa
  (intento+1)*1000 ms. La app usa timeouts de 10 s; el script usa
  60 s porque la respuesta (815 KB) tarda ~23 s a través del proxy
  de esta VM — la petición en sí es idéntica.
- **Verificación en vivo 2026-11-28:** HTTP 200,
  `application/json`. Versión del catálogo **1.0.0**;
  `catalogSource: manager`;
  `catalogReleaseId: rel_20260323181034_f5614e`;
  `catalogSnapshotId: cat_b5ad4881aac0d744a6ace433`;
  `timestamp: 1795854513911` (2026-11-28).
- **Servidores: 1,233** (65 países) — VLESS 113, VMESS 69,
  SHADOWSOCKS 1,016, TROJAN 22, sin protocolo 13 (servidores
  oficiales V2K). Por CDN: direct 1,224, cloudfront 2, cloudflare 2,
  fastly 1, bunny 1, azion 1, googlecloud 1, cachefly 1. Transportes:
  TCP 1,077, WS 134, XHTTP 11, GRPC 7, HTTPUpgrade 7, socketcustom 3,
  v2k 1, KCP 1. Seguridad: none 1,102, tls 99, reality 40. Métodos
  Shadowsocks: chacha20-ietf-poly1305 678, aes-256-gcm 284,
  aes-128-gcm 54.
- **Configs (perfiles/payloads): 63** — WS 20, XHTTP 14, httpupgrade
  12, V2K 9, socketcustom 8. 8 configs llevan plantilla de payload
  no vacía (`[crlf]`/`[split]`, p. ej. TIM/Claro/Telkomsel/Vivo).
- **Nota:** una primera descarga manual (08:15) vio 1,235 servidores;
  la descarga con el script (08:28) vio 1,233. El catálogo en vivo
  cambia entre descargas; los conteos son instantáneas.
- **El endpoint `/api/store`** del mismo worker es solo un tablón de
  anuncios comunitario (en el momento del análisis devolvió
  `{"items": []}`); no es un catálogo y no se incluye.

## 2. Descifrado — TODO descifrado, nada queda cifrado

- **Envoltorio** (`CryptoHelper.kt`):
  `base64(IV 12 B).base64(ciphertext + tag GCM 16 B)`, AES-256-GCM,
  clave de 32 B fija en el APK. Los campos `servers` y `configs` de
  la respuesta usan ese envoltorio; el mismo envoltorio protege los
  assets incluidos (`servers.enc`/`configs.enc`, que también
  descifran con la misma clave: 913 servidores / 59 configs, una
  foto más antigua) y los archivos `.v2k` cifrados.
- **Sin cifrado por campo:** tras abrir el envoltorio, todos los
  campos son texto plano — verificado con un barrido del JSON
  descifrado (0 restos con formato `iv.ciphertext`).
- **El campo `uuid` de cada servidor ES la credencial** tal como la
  usa el constructor de Xray (`XrayConfigBuilder`): UUID de
  VLESS/VMess, contraseña Shadowsocks (las claves estilo Outline en
  base64 se usan literales) o contraseña de Trojan. No es una segunda
  capa de cifrado. Los 13 servidores oficiales sin protocolo usan un
  uuid compartido (redactado en este expediente).
- **Claves en este expediente:** la clave AES del catálogo y la
  `X-API-KEY` del worker NO se guardan aquí.
  `tools/v2ray_injector.py` las carga desde
  `V2RAY_INJECTOR_CATALOG_KEY` (64 hex) y `V2RAY_INJECTOR_API_KEY`.
  Los valores viven solo en el informe del lote.

## 3. Archivos `.v2k` — VERIFIED_SYNTHETIC

- **Formato** (`V2kFileFormat.kt`, `V2kImporter.kt`):
  `V2K1|<flags hex>|<payload>`, bit 0 = cifrado AES-256-GCM con la
  misma clave del catálogo; JSON con
  `name/description/createdAt/version/xray/manual/meta`.
- **Verificación:** round-trip propio (plano y cifrado, 2/2) con
  `v2k-encode` / `v2k`. SIN muestra real exportada por la app: lo
  confirmaría un archivo `.v2k` real exportado desde la app (o un
  enlace de exportación).
- El manifest no tiene intent-filter para archivos `.v2k` (la
  importación es por selector de archivos dentro de la app).

## 4. Xray JSON y enlaces de texto — VERIFIED_SYNTHETIC

- **Xray JSON** (`XrayJsonImporter.kt`): config JSON completa de
  Xray o un objeto inbound/outbound suelto; extrae los outbounds en
  claro. Verificado con round-trip sobre un servidor real del
  catálogo.
- **Enlaces** (`VlessLinkParser.kt`): `vmess://` (JSON base64 + forma
  URI), `vless://`, `trojan://`, `ss://` (ambas formas base64 +
  `plugin=`), con los parámetros de la app (transport/type, security,
  sni, host, path, encryption, flow, serviceName, headerType,
  socketcustom, v2k*). Verificado con round-trip construyendo enlaces
  desde servidores reales del catálogo (vless, vmess, ss en sus dos
  formas, trojan: 5/5). **No existe esquema propio `v2k://`.**

## 5. Splits y librerías nativas

- `base.apk` (165,848,187 B descomprimido): SIN librerías nativas.
- `split_config.arm64_v8a.apk`: TODAS las librerías nativas (16):
  `libgojni.so` (núcleo Xray, 32 MB), `libhev-socks5-tunnel.so`,
  `libsigner.so`, `libnms.so`, `libsentry.so`, `libsentry-android.so`,
  `libapminsighta.so`, `libapminsightb.so`,
  `libapplovin-native-crash-reporter.so`,
  `libandroidx.graphics.path.so`, `libbuffer_pgl.so`,
  `libdatastore_shared_counter.so`, `libfile_lock_pgl.so`,
  `libpglarmor.so`, `libtensorflowlite_jni_gms_client.so`,
  `libtt_ugen_layout.so`.
- Assets relevantes en el base: `assets/servers.enc` (913 servidores),
  `assets/configs.enc` (59 configs), `assets/geoip.dat`,
  `assets/geosite.dat`.

## 6. Auditoría HMAC (sección 2.2 de la política)

| Ámbito | Estado | Evidencia |
|---|---|---|
| Archivo/catálogo | NOT_OBSERVED | Integridad por tags AES-256-GCM (AEAD), no por HMAC |
| Transporte VPN | No observado | Los protocolos (VLESS/VMess/SS/Trojan) se describen en el catálogo; no se trazó ningún handshake |
| Autenticación de conexión | NOT_OBSERVED | Ningún HMAC autoriza el establecimiento de la conexión; las credenciales son el `uuid` del catálogo. No se intentó ningún login en vivo |

La presencia de AES-GCM prueba integridad del sobre, no
autenticación de conexión. No se guardan claves de sesión, tokens
ni credenciales reales en este expediente.
