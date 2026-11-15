# ANALYSIS — TSC VPN Proxy 6.4.3 (versionCode 6)

Paquete: `xyz.tscvpnproxy.app`. Fuente de los hechos: `~/workspace/catalogs/NOTES.md` y `~/workspace/catalogs/tscvpn/README.md` + `TESTING.md`.
Observado: 2026-11-14/15. Expediente creado 2026-11-14 (Fase 1 del parche de 20 apps, rama `patch/20-apps`).
Estado global del expediente: **PARTIAL** (ver estados por via en MANIFEST.json y RESULTS.md).

## 1. Objetivo

Documentar el metodo de archivo / texto / catalogo de esta app con evidencia reproducible,
separando observacion, hipotesis y verificacion, sin secretos y sin afirmar lo no probado.

## 2. Muestra: como se obtuvo, hashes

- XAPK de APKPure (version de Google Play 6.4.3); hashes en MANIFEST.json > inputs.
- Sin APK, perfiles reales ni datos de usuarios en este expediente (politica §3: solo hashes publicos).
- Muestras de catalogo y de archivo: ver MANIFEST.json > inputs (las muestras reales de catalogo
  viven en `~/workspace/catalogs/tscvpn/`; aqui solo se referencian por hash).

## 3. Metodo

Familia isvsoft/StrongTeam. Valores enc: = base64url(nonce[12]||ct||tag[16]), AES-256-GCM, clave fija de formato de 32 B ASCII, sin AAD. Verificado por emulacion Unicorn de libisvcrypto.so (nativeDecrypt/nativeEncrypt/nativeSignProof) + PyCryptodome como oraculo; Python puro reproduce byte a byte la verificacion manual. Bloques SHA-256 capturados confirman HMAC estandar.

### Observacion / hipotesis / verificacion

- **Observacion:** estructuras, clases y constantes leidas del DEX / .so y de las respuestas en vivo
  (ver README de la app para el detalle por clase/funcion).
- **Hipotesis:** el pipeline descrito arriba reproduce el comportamiento de la app.
- **Verificacion:** Catalogo en vivo (2026-11-14, re-verificado por coordinador): type=full v1.0.93, 17/671, 1816/1816 valores enc:; type=servers 17/0. Self-tests de los scripts operativos: Catalogo 10/10, archivos 8/8 (scripts operativos, 2026-11-14; re-verificado por coordinador).

## 4. Herramientas, por orden, con comandos

1. Extraccion del XAPK en `~/workspace/catalogs/tscvpn/apk/` (+ `xapk/` donde existe).
2. Decompilacion / inspeccion DEX (ver DEPENDENCIES.md para versiones).
3. Emulacion nativa con Unicorn donde se indica (oraculo; no forma parte del runtime).
4. Scripts operativos en `~/workspace/catalogs/tscvpn/` (Python 3 stdlib puro):
   `python3 <Script>.py --self-test` y `python3 <Script>_archivos.py --self-test`.
5. Verificador sanitizado de este expediente: `python3 tools/verify.py` (vectores sinteticos, sin red).

Discrepancias y fallos significativos: ver RESULTS.md y las limitaciones en MANIFEST.json.

## 5. Rutas remotas (sin tokens ni endpoints sensibles)

- Descarga del catalogo con UA ISVSOFT-CloudSync/2.0 + X-ISV-Timestamp + X-ISV-Nonce + X-ISV-Signature (HMAC-SHA256 sobre ts:nonce:/api/app). Sin UA -> 403; sin firma -> 403; firma falsa -> 403; firma vieja -> 403. (La URL completa vive solo en el script operativo; aqui no se reproduce.)

La URL completa de descarga y cualquier credencial de acceso viven SOLO en el script operativo
(`~/workspace/catalogs/tscvpn/`) y en `supplied-integrations.json` cuando aplique.
Por la regla de Pedro, los JSON de resultado de catalogo NO llevan las APIs de descarga:
solo datos del catalogo, todo descifrado.

## 6. Auditoria HMAC de conexion (politica §2.2)

La mera presencia de una libreria HMAC no confirma nada. Estados por ambito:

| Ambito | Estado | Evidencia / limite |
|---|---|---|
| catalog_file_integrity | NOT_OBSERVED | Los valores enc: llevan tag GCM (integridad AEAD), no HMAC. No se observo HMAC de integridad de archivos ni de catalogo. |
| catalog_download_auth | CONFIRMED | App-Proof: firma HMAC-SHA256 sobre 'ts:nonce:/api/app' (misma clave de formato que el GCM). El worker la verifica: sin firma 403 'Missing Native App-Proof credentials', firma falsa 403 'Invalid Native App-Proof signature', firma vieja 403 'handshake expired'. Verificado en vivo 2026-11-14. Esto autentica la DESCARGA del catalogo, no la conexion VPN. Algoritmo: HMAC-SHA256. |
| crypto_derivation | NOT_OBSERVED | Clave de formato fija de 32 B derivada de constantes de libisvcrypto.so (XOR .rodata); no se observo KDF ni HMAC en la derivacion. |
| vpn_transport | NOT_OBSERVED | No se observo una conexion VPN en vivo ni MAC del transporte. |
| connection_auth | NOT_OBSERVED | No se trazo que verifica el servidor al establecer la conexion VPN. El catalogo descifrado contiene credenciales predefinidas, pero su uso en el handshake VPN no fue observado. No confundir el HMAC App-Proof del catalogo con autenticacion de conexion VPN. |

Nunca se guardan valores de claves ni entradas/salidas de hooks en este expediente.

## 7. Alcance real y cambios frente a builds previos

- Lo verificado en vivo es solo para esta version (`6.4.3`, versionCode 6); no se afirma
  compatibilidad con builds previos o posteriores sin prueba.
- Un fixture sintetico demuestra la logica implementada, NO compatibilidad con una version real
  ni conectividad remota: en RESULTS.md se distingue VERIFIED_REAL / VERIFIED_SYNTHETIC /
  REQUIRES_DEVICE / NOT_AUTHORIZED / NETWORK_UNAVAILABLE.

## 8. Archivos de este expediente

- `MANIFEST.json`, `ANALYSIS.md` (este archivo), `REPRODUCE.md`, `RESULTS.md`,
  `DEPENDENCIES.md`, `dependencies.lock.json`
- `tools/verify.py` (verificador sintetico autocontenido) + scripts de investigacion reproducibles
  copiados de `~/workspace/catalogs/tscvpn/work/` (sin secretos; ver notas en REPRODUCE.md)
- `tests/test_method.py` + `tests/fixtures/` (vectores SINTETICOS con claves TEST-ONLY)
