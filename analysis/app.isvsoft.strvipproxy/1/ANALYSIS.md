# STR VIP Proxy 1.42.5 — ANALYSIS

Fecha de verificación: 2026-11-17. Entorno: Python 3.12.3 del sistema.
Alcance: catálogo + archivos `.isc`/`.ovpn`/`.conf` + esquemas de texto.
Estado global: **PARTIAL** — catálogo VERIFIED en vivo, archivos/texto
VERIFIED_SYNTHETIC, descarga del catálogo NO cableable con el esquema
`supplied` vigente (ver §5).

## 1. Método del catálogo

- Endpoint: `GET <worker>/api/app?json=<param>&type=full`
  (variante ligera `&type=servers`). La URL completa vive en la
  constante `CATALOG_URL` del script operativo.
- Petición exacta de la app (interceptores OkHttp `LA6/a` y `Le7/a`,
  `classes3.dex`): `User-Agent: ISVSOFT-CloudSync/2.0` y, como la ruta
  contiene `api/app`, cabeceras App-Proof `X-ISV-Timestamp` (segundos
  Unix), `X-ISV-Nonce` (UUID sin guiones) y `X-ISV-Signature` de
  `ISVCrypto.c(path)` → `nativeSignProof` (`libisvcrypto.so`).
- Firma: `HMAC-SHA256(clave, "timestamp:nonce:path")` en hex minúsculo,
  `path` = ruta codificada SIN la query (`/api/app`). Firmar con la
  query incluida falla (403, verificado en vivo). El servidor rechaza
  otros User-Agent (403 `Forbidden: Unauthorized Client User-Agent.`) y
  peticiones sin prueba (403 `Forbidden: Missing Native App-Proof
  credentials.`).
- Respuesta: JSON plano (con `Content-Encoding: gzip` en el transporte),
  no cifrada a nivel de transporte. Cada valor sensible es un token
  `enc:` = `enc:` + base64url(`nonce(12) || AES-256-GCM(clave, texto)`),
  salida GCM `ciphertext || tag(16)`. Clave: constante ASCII de 32 bytes
  (`CRYPTO_KEY` en el script operativo), recuperada de `libisvcrypto.so`
  (constantes de 64 bits ofuscadas con XOR, ensambladas en la pila en
  `nativeSignProof`, 0x62e4). Es la MISMA clave para HMAC y AES.
  Es una constante de formato de la app, no una credencial de usuario.
- Verificación: (a) descifrado comprobado contra la librería nativa
  emulada (Unicorn: token conocido → `78.46.243.53`, y salidas de
  `nativeEncrypt`); (b) `cryptography` sobre los 1.951 valores `enc:`
  de vivo + incrustados (1.888 vivo, 40 incrustados; 0 fallos); (c) el
  cifrado en Python puro lo descifra la librería nativa y viceversa;
  (d) el tag GCM rechaza valores manipulados. El AES-256-GCM de los
  scripts es una implementación en Python puro (solo stdlib; no hay AES
  en la stdlib), validada por ese cruce; no es una suposición.
- Incrustado: assets `servers.json`/`settings.json`/`tweaks.json` v1.0.0
  (9 servidores, 11 tweaks).

## 2. Catálogo en vivo (2026-11-17)

| Fuente | Versión | Servidores | Tweaks |
|---|---|---|---|
| Assets incrustados (`--apks`, v1.0.0) | 1.0.0 | 9 | 11 |
| GET oficial `type=full` | **1.0.31** | **21** | **686** |
| GET oficial `type=servers` | **1.0.31** | **21** | — |

- Secciones: `meta`, `servers`, `tweaks`, `settings` (`miscSettings`,
  `predefinedCredentials`, `certProfiles`).
- Servidores: 21/21 `isOnline`. Protocolos: OVPN 14, HYSTERIA 3,
  V2RAY 2, SSH 2. Tweaks: OVPN 621, HYSTERIA 50, SSH 9, V2RAY 6.
- Valores `enc:` descifrados en vivo: **1.888/1.888, 0 fallos**.
  No queda ningún `enc:` sin descifrar en `live.json` (0 ocurrencias).
- `run()` offline sobre la respuesta guardada (`work/live_full.bin`,
  487.493 B) devuelve el mismo documento en 1,53 s (tope del worker:
  20 s). `run()` con entrada inválida devuelve `None`.
- El JSON de resultado NO incluye las APIs de descarga.

## 3. Archivos `.isc` / `.ovpn` / `.conf` y texto

- `.isc`: texto UTF-8. Importación `LT6/F1` → `LT6/E.b`: si empieza por
  `isv-config://` → se quitan 13 caracteres y `LT6/E.a` al resto; si
  empieza por `{` → `LT6/E.d` (Gson → `SharedConfig`); si no →
  `LT6/E.a` al texto completo y el mismo despacho sobre el resultado.
  `LT6/E.a` = descifrado ISVCrypto del valor (token `enc:`, añadiendo
  el prefijo si falta). `SharedConfig{protocol, locked, configJson,
  expirationDays, expirationTimestamp, burnAfterRead, message}`;
  `configJson` se parsea según `protocol` (Ssh/OpenVpn/V2Ray/Hysteria).
  El decodificador devuelve el `configJson` parseado con todos sus
  campos, sin aplicar bloqueo/caducidad/burn-after-read (se reportan).
- Enlace `isv-config://`: `isv-config://` + token `enc:` del JSON de
  `SharedConfig`. El decodificador prueba primero el descifrado (ruta
  real) y, como fallback defensivo, base64 del JSON.
- Códigos `ISV-`: la app los busca en caché local (demos pre-cargados
  `ISV-SSH-LOCK`, `ISV-OVPN-FREE`) o GET `/api/v1/config/share/{code}`
  en el mismo worker (sin App-Proof). Verificado en vivo solo el
  404 (`{"success": false, "error": "Shared config not found or
  expired."}`). `decode()` devuelve el código como marcador.
- `.ovpn`/`.conf`: texto plano OpenVPN (libovpn3); la app rechaza ZIP.
  El decodificador parsea directivas y bloques inline sin cambiar valores.
- `.sks`: no hay nada (ninguna referencia en manifiesto, DEX ni
  importación). No se construyó decodificador `.sks`.
- Manifiesto: NO registra asociación de archivos ni esquema URI propio;
  la importación es desde el selector de archivos / portapapeles /
  pegado de enlace dentro de la app.
- Enlaces de protocolo (`vmess://`, `vless://`, `trojan://`, `ss://`,
  texto WireGuard): formatos estándar, ya registrados genéricamente;
  no se re-registran.

## 4. Auditoría HMAC

- Archivos/catálogo: integridad por tags AES-256-GCM (AEAD), no HMAC.
- Derivación: ninguna (clave fija de formato).
- Transporte VPN: no revisado.
- Autenticación de conexión: **HMAC-SHA256 App-Proof observado** (ver
  MANIFEST.json). La presencia de HMAC aquí SÍ autentica la petición
  al worker del catálogo, verificada en vivo con 403 sin ella.

## 5. Bloqueo de integración del catálogo (hallazgo principal)

La petición exacta NO puede expresarse en
`cloud/web/content/supplied-integrations.json` `requests[]`. Evidencia
en el head `5df9fc50` (ver REPORT.md §4):

- `supplied-integrations.mjs:suppliedRequests()` solo copia cabeceras
  estáticas, un `secretHeader` (UN valor estático de entorno como UNA
  cabecera) y `sessionHeaders` genéricas (`X-App-Device` UUID,
  `X-App-Ts`, `X-App-Nonce` aleatorio). No hay ningún campo de firma.
- `server-vpn-provider.mjs`: 0 ocurrencias de `HMAC`, `createHmac`,
  `X-ISV`, `App-Proof`. `supplied-integrations.json`: 0 campos HMAC.
- La firma necesita, POR PETICIÓN: timestamp actual + nonce nuevo +
  `HMAC-SHA256(clave, "timestamp:nonce:/api/app")`. Ningún `requests[]`
  estático puede producirla. Inventar un `requests[]` con la firma
  sería falso: el servidor lo rechazaría con 403 (la firma caduca y el
  nonce no se reutiliza).
- Opciones (decisión pendiente de Pedro/Codex): (a) extender el esquema
  con un tipo de firma HMAC por secreto de entorno; (b) broker dedicado
  en `server-vpn-provider.mjs` (patrón C8 existente para peticiones con
  firma/hash, p. ej. `mm-tunnel`); (c) dejar el catálogo sin cablear.
  En cualquier caso la clave de firma debe vivir como secreto de
  entorno, nunca en Git. La entrada supplied propuesta es `FILE_ONLY`
  (`requests:[]`) hasta que se resuelva.

## 6. Pendientes

1. Archivo real exportado por la app (`.isc` / `isv-config://` /
   `.ovpn`) para confirmar el extremo a extremo.
2. Código de nube `ISV-` real (forma de éxito del endpoint share).
3. Ortografía exacta del enlace WireGuard aceptado.
4. Decisión de firma HMAC del catálogo (ver §5).
