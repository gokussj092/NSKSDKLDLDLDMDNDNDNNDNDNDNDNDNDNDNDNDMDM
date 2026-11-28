# ANALYSIS — Peru VPN 4.1.2 (`com.peru.vpn`, code 412)

- **App:** Peru VPN 4.1.2 (versionCode 412)
- **APK analizado:** `Peru_VPN_4.1.2_4_3tyo.apks` (55,060,859 bytes),
  SHA-256
  `5660422496a22c98f382080988f5e17986a2e3c304b9ad4e5cbe1e08a0999d03`
- **Fecha:** 2026-11-28
- **Alcance:** catálogo en vivo + catálogo incluido. Sin push, sin
  despliegue desde este trabajo.
- **Veredicto: EL CATÁLOGO ABRE EN VIVO (Version 532, 390 servidores).
  La app NO define formato de archivo ni esquema de texto propios
  (VERIFIED_ABSENT).**

> Peru VPN es un rebrand de TunnelDOOM — el código vive bajo
> `com.tunneldoom.http` / `com.tunneldoom.sshservice` y la criptografía
> es idéntica a TunnelDOOM 4.3.5, verificada en el fuente descompilado
> de ESTA build. El hallazgo principal de 4.1.2 es que el host del
> catálogo YA es el fijo: `free.tunneldoom.space`. El host muerto
> `web.tunneldoom.space` no aparece en ningún DEX de esta build
> (0 ocurrencias), así que la entrada del repo que apunta a él está
> obsoleta y debe actualizarse a `free.tunneldoom.space` al integrar.

## 1. Catálogo en vivo — VERIFIED_REAL

- **Observación:** `ConfigUpdateco.doInBackground` (descompilado de
  esta build) hace un GET plano a
  `https://free.tunneldoom.space/config.json`, sin cabeceras propias,
  sin autenticación, sin token.
- **Verificación en vivo 2026-11-28:** HTTP 200, 641,872 bytes,
  SHA-256
  `eb491df489c5bedef2badc6fdac81bb3c11634ef12fe598eb2842dab252a4b4e`.
  Descargado dos veces (prueba directa + script final); ambas
  descifran y dan el mismo JSON. `web.tunneldoom.space` no responde
  (curl: HTTP 000).
- **Contenido:** Version **532**, **390 servidores**, 1,812 campos
  cifrados no vacíos descifrados (JSON descifrado 423,235 bytes,
  SHA-256
  `57ab5536abf20f929354e0888d61ffe23130695974ba6f8febf6ba12a993db23`).
  Sin marcador premium: los 390 vienen sin distinción premium/free.
  Payloads: 243 servidores con `Payload` no vacío (viven dentro de
  cada servidor; no hay sección separada). Redes: sin sección
  separada; cada servidor trae `sPais` y `FLAG` (56 FLAGs distintos;
  76 valores distintos de `sPais`). Tipos: 111 SSL, 149 directos,
  17 inject, 7 UDP, 2 SlowDNS, 14 BHTTP, 49 `isV2ray`. `V2rayConfig`
  (66 no vacíos, todo en claro): 44 enlaces `vless://`, 19 JSON de
  configuración V2Ray, 2 enlaces `hysteria2://`, 1 texto de payload
  multiparte. `ReleaseNotes` presentes. Barrido final: ningún campo
  en claro contiene tokens Base64 largos sospechosos; `Slowchave`
  son claves hex de 64 caracteres (32 bytes), valor en claro.
- **Comparación:** TunnelDOOM 4.3.5 era Version 531, 391 servidores
  (2026-11-27). Es el mismo feed compartido, un día más nuevo.

## 2. Criptografía — verificada en el fuente de ESTA build

- **Sobre:** `StringCrypter.processString('d')`: Base64 → XOR con
  SHA-256 de una etiqueta fija → quitar 32 caracteres de salt hex.
  Idéntico a TunnelDOOM.
- **Campos:** `NoobCrypt`: AES-256-CBC, IV de 16 ceros, PKCS7; clave
  SHA-256 de una cadena ofuscada del APK (`NoobPass.star`, XOR con
  una máscara de 4 caracteres, invertida). Idéntico. 13 campos:
  `ServerUser`, `ServerPass`, `ServerIP`, `ProxyIP`, `Payload`,
  `SNI`, `Slowchave`, `Nameserver`, `Slowdns`, `UdpBuffer`, `UdpDown`,
  `UdpUp`, `V2rayConfig`.
- **Prueba definitiva:** el catálogo vivo 532 descifra completo con
  las claves viejas — no rotaron.
- `UrlEncryption` (AES/CBC) también idéntica; se usa para otras URLs
  de la app, no para el catálogo.
- **Claves en este expediente:** los valores de formato NO se
  guardan aquí. `tools/codec.py` carga las claves derivadas de 32
  bytes desde `PERU_CATALOG_KEY_HEX` / `PERU_FIELD_KEY_HEX` (o
  `PERU_TEST_KEYS=1` para las claves sintéticas de los tests). La
  derivación está documentada arriba sin literales; los valores
  viven solo en el informe del lote.

## 3. Archivos y textos — VERIFIED_ABSENT

- **Archivo de config propio: no existe.** DEX: 0 literales `.sks`,
  `.td` o `.peru`; manifest: ningún intent-filter de archivo (solo
  `https`, `sms`, `tel:`). Por eso NO se entrega file decoder: no
  hay nada que decodificar.
- **Texto propietario: no existe.** DEX: solo import manual estándar
  (`menu_item_import_config_manually_{ss,http,socks,vless,vmess,
  trojan,hysteria2,wireguard}`), portapapeles y QR. No se inventa
  ningún prefijo Peru VPN.
- **Catálogo incluido `noobdev.txt`:** verificado — descifra con el
  codec (Version 2, 8 servidores plantilla Perú, 40 campos
  cifrados). `res/raw/noobdev.txt` del base.apk 4.1.2, SHA-256
  `dc73b38eda17c0395621845d3d6f4fb185c43d023873d092f92e208e40334721`.
  Contenido distinto al de TunnelDOOM 4.3.5 (Version 3, 1 servidor
  `prueba`); misma cripto.

## 4. Auditoría HMAC (sección 2.2 de la política)

| Ámbito | Estado | Evidencia |
|---|---|---|
| Archivo/catálogo | NOT_OBSERVED | Integridad por construcción (XOR + AES-CBC/PKCS7); ningún HMAC/MAC en el sobre ni en los campos |
| Transporte VPN | No observado | Los protocolos (SSL/Direct/UDP/SlowDNS/V2Ray) se describen en el catálogo; no se trazó ningún handshake |
| Autenticación de conexión | NOT_OBSERVED | Ningún HMAC autoriza el establecimiento de la conexión; las credenciales son usuario/contraseña del catálogo. No se intentó ningún login en vivo |

La ausencia de HMAC no es un fallo del formato: el sobre y los
campos se autentican por descifrado válido (PKCS7 + esquema JSON),
no por MAC. No se guardan claves de sesión, tokens ni credenciales
reales en este expediente.

## 5. Splits extraídos

| Split | Contenido relevante |
|---|---|
| `base.apk` (47,7 MB) | `classes.dex`, `classes2.dex`, `classes3.dex`; `res/raw/noobdev.txt`; `assets/config/…/config.json`; sin librerías nativas |
| `split_config.arm64_v8a.apk` (22,2 MB) | Todas las librerías nativas (`libgojni.so` 30 MB, `libv2ray.so`, `libtun2socks.so`, …). Ninguna interviene en el descifrado del catálogo (es Java) |
| `split_config.es.apk` (127 KB) | Solo manifiesto |
| `split_config.xhdpi.apk` (453 KB) | Recursos, incluido el icono 1280×1280 |

Diferencia con TunnelDOOM 4.3.5: este split NO trae
`libhev-socks5-tunnel.so`.

## 6. Pendiente

- **Asset `assets/config/config/…/config.json`** (11 niveles
  `config/`, 2,949 B, SHA-256
  `4dfe2f21b7151f29b244d2d44fa632b80329123e5c179ba95d8c19e3b092b829`):
  mismo asset sin explicar que en TunnelDOOM 4.3.5 (forma EncServer /
  Nonce / Hash, AES-GCM). Ningún código DEX referencia `EncServer`
  ni esa ruta en esta build tampoco. No bloquea el catálogo.
- Sin muestra de exportación real no hay file decoder que verificar:
  la app no exporta a un formato propio (su export es texto/URI
  estándar por portapapeles/compartir).
