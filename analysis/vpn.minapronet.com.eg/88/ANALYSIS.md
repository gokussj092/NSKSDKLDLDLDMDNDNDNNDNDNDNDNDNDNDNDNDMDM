# ANALYSIS — MinaProNet 88.0.0 (versionCode 88)

Paquete: `vpn.minapronet.com.eg`. Fuente de los hechos: `~/workspace/catalogs/NOTES.md` y `~/workspace/catalogs/minapronet/README.md` + `TESTING.md`.
Observado: 2026-11-14/15. Expediente creado 2026-11-14 (Fase 1 del parche de 20 apps, rama `patch/20-apps`).
Estado global del expediente: **PARTIAL** (ver estados por via en MANIFEST.json y RESULTS.md).

## 1. Objetivo

Documentar el metodo de archivo / texto / catalogo de esta app con evidencia reproducible,
separando observacion, hipotesis y verificacion, sin secretos y sin afirmar lo no probado.

## 2. Muestra: como se obtuvo, hashes

- XAPK de APKPure (version de Google Play 88.0.0); hashes en MANIFEST.json > inputs.
- Sin APK, perfiles reales ni datos de usuarios en este expediente (politica §3: solo hashes publicos).
- Muestras de catalogo y de archivo: ver MANIFEST.json > inputs (las muestras reales de catalogo
  viven en `~/workspace/catalogs/minapronet/`; aqui solo se referencian por hash).

## 3. Metodo

k(): quitar 3 caracteres en posiciones 5-7 y 3 en 20-22 -> Base64 -> xde (Base64 -> reverse -> ROT+20 letras, nativo libchzcore.so) -> dc: Base64 -> salt[0:16]||IV[16:32]||ct -> PBKDF2-HmacSHA1(pw, salt, 10000 iter, clave 256 bits) -> AES-256-CBC/PKCS7 -> JSON. La URL del updater NO esta en el DEX: la construye MinaCore.nativeGetConfigUrl (0x10423c en libminacore.so), recuperada emulando la funcion con Unicorn. .mina: ecr(ConfigCustom JSON, 'u') -> xec -> Base64 -> insertar los mismos 3 caracteres aleatorios ([A-Z][0-9][a-z]) en 20-22 y de nuevo en 5-7. Sitio (modo --site, metodo v19 de DataPhreak): blob 'config' Base64 = salt[16]||IV[16]||AES-256-CBC, clave PBKDF2-HmacSHA1 (10000 iter); luego correccion Caesar -1 en pubkey, psiphonEntry, slowDnsPubKey, slowDnsPubKeyV2ray, udpAuth, v2rayEntry, slowDnsLinkV2ray.

### Observacion / hipotesis / verificacion

- **Observacion:** estructuras, clases y constantes leidas del DEX / .so y de las respuestas en vivo
  (ver README de la app para el detalle por clase/funcion).
- **Hipotesis:** el pipeline descrito arriba reproduce el comportamiento de la app.
- **Verificacion:** Updater en vivo vacio (200, 14 B) luego 404; sitio update_required (v88/v89); control k() sobre slowdns_config.json en vivo (v4, 7/54); servidores publicos 213/33 paises (11-14) -> 234/35 (11-15) -> 205/31 paises (11-17). Self-tests de los scripts operativos: Catalogo 21/21, archivos 12/12 (scripts operativos, 2026-11-17).

## 4. Herramientas, por orden, con comandos

1. Extraccion del XAPK en `~/workspace/catalogs/minapronet/apk/` (+ `xapk/` donde existe).
2. Decompilacion / inspeccion DEX (ver DEPENDENCIES.md para versiones).
3. Emulacion nativa con Unicorn donde se indica (oraculo; no forma parte del runtime).
4. Scripts operativos en `~/workspace/catalogs/minapronet/` (Python 3 stdlib puro):
   `python3 <Script>.py --self-test` y `python3 <Script>_archivos.py --self-test`.
5. Verificador sanitizado de este expediente: `python3 tools/verify.py` (vectores sinteticos, sin red).

Discrepancias y fallos significativos: ver RESULTS.md y las limitaciones en MANIFEST.json.

## 5. Rutas remotas (sin tokens ni endpoints sensibles)

- Updater: GET simple sin cabeceras -> k(body, 'm') -> GettterConfig; luego GET del catalogo -> k(body, server_pass) -> MinaConfig. Servidores publicos: JSON plano sin cifrar. Sitio: POST con cabeceras x-hwid / x-timestamp / x-signature (HMAC-SHA256) / x-app-version / x-package, UA okhttp/4.12.0. (Las URLs completas viven solo en el script operativo; aqui no se reproducen.)

La URL completa de descarga y cualquier credencial de acceso viven SOLO en el script operativo
(`~/workspace/catalogs/minapronet/`) y en `supplied-integrations.json` cuando aplique.
Por la regla de Pedro, los JSON de resultado de catalogo NO llevan las APIs de descarga:
solo datos del catalogo, todo descifrado.

## 6. Auditoria HMAC de conexion (politica §2.2)

La mera presencia de una libreria HMAC no confirma nada. Estados por ambito:

| Ambito | Estado | Evidencia / limite |
|---|---|---|
| catalog_file_integrity | NOT_OBSERVED | k() no incluye MAC/HMAC: la integridad se comprueba por parseo JSON tras el descifrado. El catalogo publico es JSON plano sin firma. |
| catalog_download_auth | NOT_OBSERVED | El updater es un GET simple sin firma; el catalogo publico tambien es un GET simple sin firma. El endpoint del sitio SI usa HMAC (ver connection_auth), pero para autenticar la PETICION al sitio, no la descarga del updater. |
| crypto_derivation | NOT_OBSERVED | PBKDF2-HmacSHA1 (10000 iter) deriva la clave AES; el HMAC aqui es parte de PBKDF2, no una firma de autenticacion observada. |
| vpn_transport | NOT_OBSERVED | No se observo una conexion VPN en vivo ni MAC del transporte. |
| connection_auth | CONFIRMED | Endpoint del sitio: x-signature = HMAC-SHA256 de 'hwid:ts:body'. Verificado en vivo 2026-11-15: firma mala -> conexion cerrada sin respuesta; sin x-signature -> HTTP 400; firma valida -> HTTP 200 update_required. Esto autentica la PETICION al endpoint del sitio; NO es autenticacion de conexion VPN (no se trazo el handshake VPN). Algoritmo: HMAC-SHA256. |

Nunca se guardan valores de claves ni entradas/salidas de hooks en este expediente.

## 7. Alcance real y cambios frente a builds previos

- Lo verificado en vivo es solo para esta version (`88.0.0`, versionCode 88); no se afirma
  compatibilidad con builds previos o posteriores sin prueba.
- Un fixture sintetico demuestra la logica implementada, NO compatibilidad con una version real
  ni conectividad remota: en RESULTS.md se distingue VERIFIED_REAL / VERIFIED_SYNTHETIC /
  REQUIRES_DEVICE / NOT_AUTHORIZED / NETWORK_UNAVAILABLE.

## 8. Archivos de este expediente

- `MANIFEST.json`, `ANALYSIS.md` (este archivo), `REPRODUCE.md`, `RESULTS.md`,
  `DEPENDENCIES.md`, `dependencies.lock.json`
- `tools/verify.py` (verificador sintetico autocontenido) + scripts de investigacion reproducibles
  copiados de `~/workspace/catalogs/minapronet/work/` (sin secretos; ver notas en REPRODUCE.md)
- `tests/test_method.py` + `tests/test_public_servers.py` + `tests/fixtures/` (vectores SINTETICOS con claves TEST-ONLY)

## 9. Actualización 2026-11-17 — servidores públicos cableados

- El APK de Play 88.0.0 es byte-idéntico al ya analizado (base.apk y split arm64-v8a con los
  mismos SHA-256); el método no cambió. Re-trabajo: `minapronet.updater` y `minapronet.json`
  ya NO EXISTEN en el repo (listado GitHub 2026-11-17; updater HTTP 404) y `minapronet.site`
  sigue en `update_required` para las versiones 88–100 (probadas 88, 89, 90, 91, 92 y 100).
- El ÚNICO catálogo que la app descarga en vivo hoy es el de servidores públicos
  `v2ray-verified.json` (PublicServersActivity): 205 entradas, 205 online, 31 países.
- Cableado: entrada supplied `minapronet-vpn` con un `requests[]` (GET, UA `okhttp/4.12.0`,
  sin body) + `catalogState: CONNECTED`; la tarjeta aparece sola vía
  `SUPPLIED_CATALOG_ITEMS` (sin cambio en `server-vpn-catalog.mjs`); el broker genérico
  `downloadSupplied` la descarga; el worker la abre con la rama nueva de
  `supplied_bridge.py` `decode_one()` → `decode_public_servers()` (aditivo, puro, sin red).
- MinaConfig sigue SIN cablear; el flujo de nube por clave de 27 caracteres queda intacto.
- Queda un canal nativo sin resolver: `ServerSyncManager` / `MinaCore.nativeFetchConfig` +
  `nativeSetServerUrl` (libminacore.so, URL ofuscada en el código nativo); solo una captura
  en vivo en un teléfono con la app de Play podría revelar su URL.
- La app NO define esquema `minapronet://` (manifiesto + DEX, 2026-11-17): al exportar muestra
  el texto `Config Key : <clave-de-27>` y copia solo la clave; `parse_cloud_key()` acepta la
  clave suelta, ese texto o un enlace pegado solo como tolerancia.
