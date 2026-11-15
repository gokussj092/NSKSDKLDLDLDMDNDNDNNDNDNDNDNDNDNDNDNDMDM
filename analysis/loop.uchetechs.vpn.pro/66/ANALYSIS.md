# ANALYSIS — UT Loop Pro VPN 23.11.26 (versionCode 66)

Paquete: `loop.uchetechs.vpn.pro`. Fuente de los hechos: `~/workspace/catalogs/NOTES.md` y `~/workspace/catalogs/utloop/README.md` + `TESTING.md`.
Observado: 2026-11-14/15. Expediente creado 2026-11-14 (Fase 1 del parche de 20 apps, rama `patch/20-apps`).
Estado global del expediente: **PENDING** (ver estados por via en MANIFEST.json y RESULTS.md).

## 1. Objetivo

Documentar el metodo de archivo / texto / catalogo de esta app con evidencia reproducible,
separando observacion, hipotesis y verificacion, sin secretos y sin afirmar lo no probado.

## 2. Muestra: como se obtuvo, hashes

- XAPK de APKPure (version de Google Play 23.11.26); hashes en MANIFEST.json > inputs.
- Sin APK, perfiles reales ni datos de usuarios en este expediente (politica §3: solo hashes publicos).
- Muestras de catalogo y de archivo: ver MANIFEST.json > inputs (las muestras reales de catalogo
  viven en `~/workspace/catalogs/utloop/`; aqui solo se referencian por hash).

## 3. Metodo

Sobre JSON {data, sig}: data = base64(nonce[12]||ct||tag[16]), AES-256-GCM sin AAD, clave = SHA-256(cadena fija de esquema) XOR mascara fija de 32 B (util/t.java). sig = RSA-SHA256 2048 bits sobre los bytes de data. Config descifrado: {Version, PremiumRev, Notice, Servers[], Tweaks[]}. Reserva incrustada (util/h.java, campo f19289b): blob de 1157 B, doble Base64 + StringFog, ABRE con la clave de formato (tag GCM valido): Version 1.0, 1 servidor + 1 tweak de ejemplo ('INTERNET NEEDED TO LOAD SERVERS').

### Observacion / hipotesis / verificacion

- **Observacion:** estructuras, clases y constantes leidas del DEX / .so y de las respuestas en vivo
  (ver README de la app para el detalle por clase/funcion).
- **Hipotesis:** el pipeline descrito arriba reproduce el comportamiento de la app.
- **Verificacion:** Sondeo en vivo (2026-11-14): nonce 200; premium 403 not_entitled; ota/locked 401 access_required. Reserva incrustada abre (v1.0, 1/1). Self-tests de los scripts operativos: Catalogo 13/13, archivos 7/7 (scripts operativos, 2026-11-14).

## 4. Herramientas, por orden, con comandos

1. Extraccion del XAPK en `~/workspace/catalogs/utloop/apk/` (+ `xapk/` donde existe).
2. Decompilacion / inspeccion DEX (ver DEPENDENCIES.md para versiones).
3. Emulacion nativa con Unicorn donde se indica (oraculo; no forma parte del runtime).
4. Scripts operativos en `~/workspace/catalogs/utloop/` (Python 3 stdlib puro):
   `python3 <Script>.py --self-test` y `python3 <Script>_archivos.py --self-test`.
5. Verificador sanitizado de este expediente: `python3 tools/verify.py` (vectores sinteticos, sin red).

Discrepancias y fallos significativos: ver RESULTS.md y las limitaciones en MANIFEST.json.

## 5. Rutas remotas (sin tokens ni endpoints sensibles)

- API con tres endpoints con el mismo sobre cifrado (util/t.java). POST /v1/nonce -> 200 con nonce (verificado en vivo, dos veces). Sin JWT/token: premium 403, ota/locked 401. (Las URLs completas y la clave API viven solo en el script operativo; aqui no se reproducen.)

La URL completa de descarga y cualquier credencial de acceso viven SOLO en el script operativo
(`~/workspace/catalogs/utloop/`) y en `supplied-integrations.json` cuando aplique.
Por la regla de Pedro, los JSON de resultado de catalogo NO llevan las APIs de descarga:
solo datos del catalogo, todo descifrado.

## 6. Auditoria HMAC de conexion (politica §2.2)

La mera presencia de una libreria HMAC no confirma nada. Estados por ambito:

| Ambito | Estado | Evidencia / limite |
|---|---|---|
| catalog_file_integrity | CONFIRMED | El sobre es JSON {data, sig}; sig = RSA-SHA256 (2048 bits, e=65537) sobre los bytes de data, verificada con la clave publica incrustada. No es HMAC, pero es el mecanismo de integridad del catalogo. Los tests de este expediente verifican RSA-SHA256 con una clave de PRUEBA generada aqui (no la real). Algoritmo: RSA-SHA256 (firma, no HMAC). |
| catalog_download_auth | NOT_OBSERVED | El acceso se controla por JWT de entitlement y token OTA (Play Integrity), no por HMAC observado. |
| crypto_derivation | NOT_OBSERVED | Clave AES = SHA-256 de una cadena fija de esquema XOR mascara fija de 32 B; no se observo HMAC en la derivacion. |
| vpn_transport | NOT_OBSERVED | No se observo una conexion VPN en vivo ni MAC del transporte. |
| connection_auth | NOT_OBSERVED | No se trazo autenticacion de conexion VPN. La firma RSA del sobre autentica el catalogo, no la conexion. |

Nunca se guardan valores de claves ni entradas/salidas de hooks en este expediente.

## 7. Alcance real y cambios frente a builds previos

- Lo verificado en vivo es solo para esta version (`23.11.26`, versionCode 66); no se afirma
  compatibilidad con builds previos o posteriores sin prueba.
- Un fixture sintetico demuestra la logica implementada, NO compatibilidad con una version real
  ni conectividad remota: en RESULTS.md se distingue VERIFIED_REAL / VERIFIED_SYNTHETIC /
  REQUIRES_DEVICE / NOT_AUTHORIZED / NETWORK_UNAVAILABLE.

## 8. Archivos de este expediente

- `MANIFEST.json`, `ANALYSIS.md` (este archivo), `REPRODUCE.md`, `RESULTS.md`,
  `DEPENDENCIES.md`, `dependencies.lock.json`
- `tools/verify.py` (verificador sintetico autocontenido) + scripts de investigacion reproducibles
  copiados de `~/workspace/catalogs/utloop/work/` (sin secretos; ver notas en REPRODUCE.md)
- `tests/test_method.py` + `tests/fixtures/` (vectores SINTETICOS con claves TEST-ONLY)
