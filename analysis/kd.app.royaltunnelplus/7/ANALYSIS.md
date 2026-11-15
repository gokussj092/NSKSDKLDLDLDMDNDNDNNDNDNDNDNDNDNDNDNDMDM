# ANALYSIS — Royal Tunnel VPN 7.0 (versionCode 7)

Paquete: `kd.app.royaltunnelplus`. Fuente de los hechos: `~/workspace/catalogs/NOTES.md` y `~/workspace/catalogs/royaltunnel/README.md` + `TESTING.md`.
Observado: 2026-11-14/15. Expediente creado 2026-11-14 (Fase 1 del parche de 20 apps, rama `patch/20-apps`).
Estado global del expediente: **PARTIAL** (ver estados por via en MANIFEST.json y RESULTS.md).

## 1. Objetivo

Documentar el metodo de archivo / texto / catalogo de esta app con evidencia reproducible,
separando observacion, hipotesis y verificacion, sin secretos y sin afirmar lo no probado.

## 2. Muestra: como se obtuvo, hashes

- XAPK de APKPure (version de Google Play 7.0); hashes en MANIFEST.json > inputs.
- Sin APK, perfiles reales ni datos de usuarios en este expediente (politica §3: solo hashes publicos).
- Muestras de catalogo y de archivo: ver MANIFEST.json > inputs (las muestras reales de catalogo
  viven en `~/workspace/catalogs/royaltunnel/`; aqui solo se referencian por hash).

## 3. Metodo

Sobre: Base64 -> XXTEA modificado (delta 0x9A7393B4, clave = primeros 16 B del UTF-8 de 33x U+3164) -> JSON. Servidores con Hw0.a (AES-256/CFB/NoPadding, clave SHA-256 de material de 83 caracteres, IV fijo); tweaks con uE0.a (AES-256/CBC/PKCS7, clave = ASCII hex del MD5 de material de 63 caracteres, IV fijo). Flag de tweaks en TEXTO PLANO ('NOOB_DEV'). .ROY: Nbencrypt/Nbdecrypt (NoobCrypt, libwg-pro.so, 4 modos con la misma clave fija de 32 B): modo 0 = nonce12||AES-256-GCM||tag16; modo 1 = iv16||AES-256-CBC/PKCS7; modo 2 = nonce16||ChaCha20; modo 3 = nonce12||ChaCha20-Poly1305||tag16. El .ROY usa modo 1 fuera y modo 0 dentro.

### Observacion / hipotesis / verificacion

- **Observacion:** estructuras, clases y constantes leidas del DEX / .so y de las respuestas en vivo
  (ver README de la app para el detalle por clase/funcion).
- **Hipotesis:** el pipeline descrito arriba reproduce el comportamiento de la app.
- **Verificacion:** Catalogo en vivo (2026-11-14): v5.43, 29 servidores, 105 tweaks, 0 errores de campo; respaldo v5.17, 27/100. Self-tests de los scripts operativos: Catalogo 15/15, archivos 18/18 (scripts operativos, 2026-11-14).

## 4. Herramientas, por orden, con comandos

1. Extraccion del XAPK en `~/workspace/catalogs/royaltunnel/apk/` (+ `xapk/` donde existe).
2. Decompilacion / inspeccion DEX (ver DEPENDENCIES.md para versiones).
3. Emulacion nativa con Unicorn donde se indica (oraculo; no forma parte del runtime).
4. Scripts operativos en `~/workspace/catalogs/royaltunnel/` (Python 3 stdlib puro):
   `python3 <Script>.py --self-test` y `python3 <Script>_archivos.py --self-test`.
5. Verificador sanitizado de este expediente: `python3 tools/verify.py` (vectores sinteticos, sin red).

Discrepancias y fallos significativos: ver RESULTS.md y las limitaciones en MANIFEST.json.

## 5. Rutas remotas (sin tokens ni endpoints sensibles)

- Descarga del catalogo: GET plano sin headers (HttpURLConnection). Respuesta HTTP 200, 276080 B, una linea Base64. (La URL completa vive solo en el script operativo; aqui no se reproduce.)

La URL completa de descarga y cualquier credencial de acceso viven SOLO en el script operativo
(`~/workspace/catalogs/royaltunnel/`) y en `supplied-integrations.json` cuando aplique.
Por la regla de Pedro, los JSON de resultado de catalogo NO llevan las APIs de descarga:
solo datos del catalogo, todo descifrado.

## 6. Auditoria HMAC de conexion (politica §2.2)

La mera presencia de una libreria HMAC no confirma nada. Estados por ambito:

| Ambito | Estado | Evidencia / limite |
|---|---|---|
| catalog_file_integrity | NOT_OBSERVED | El catalogo usa XXTEA + AES-CFB/CBC sin MAC/HMAC observado; la integridad se comprueba por parseo JSON y conteo de campos (0 errores), no por HMAC. |
| catalog_download_auth | NOT_OBSERVED | GET plano sin headers ni firma observada. |
| crypto_derivation | NOT_OBSERVED | Claves derivadas por SHA-256/MD5 de material fijo; no se observo HMAC en la derivacion. |
| vpn_transport | NOT_OBSERVED | No se observo una conexion VPN en vivo ni MAC del transporte. |
| connection_auth | NOT_OBSERVED | No se trazo autenticacion de conexion. La mera presencia de librerias criptograficas en libwg-pro.so no confirma nada. |

Nunca se guardan valores de claves ni entradas/salidas de hooks en este expediente.

## 7. Alcance real y cambios frente a builds previos

- Lo verificado en vivo es solo para esta version (`7.0`, versionCode 7); no se afirma
  compatibilidad con builds previos o posteriores sin prueba.
- Un fixture sintetico demuestra la logica implementada, NO compatibilidad con una version real
  ni conectividad remota: en RESULTS.md se distingue VERIFIED_REAL / VERIFIED_SYNTHETIC /
  REQUIRES_DEVICE / NOT_AUTHORIZED / NETWORK_UNAVAILABLE.

## 8. Archivos de este expediente

- `MANIFEST.json`, `ANALYSIS.md` (este archivo), `REPRODUCE.md`, `RESULTS.md`,
  `DEPENDENCIES.md`, `dependencies.lock.json`
- `tools/verify.py` (verificador sintetico autocontenido) + scripts de investigacion reproducibles
  copiados de `~/workspace/catalogs/royaltunnel/work/` (sin secretos; ver notas en REPRODUCE.md)
- `tests/test_method.py` + `tests/fixtures/` (vectores SINTETICOS con claves TEST-ONLY)
