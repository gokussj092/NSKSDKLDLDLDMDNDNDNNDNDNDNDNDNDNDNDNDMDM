# ANALYSIS — PPH GOOD VPN 1.7.2 (versionCode 75)

Paquete: `com.skphvpn.mm`. Fuente de los hechos: `~/workspace/catalogs/NOTES.md` y `~/workspace/catalogs/pph/README.md` + `TESTING.md`.
Observado: 2026-11-14/15. Expediente creado 2026-11-14 (Fase 1 del parche de 20 apps, rama `patch/20-apps`).
Estado global del expediente: **VERIFIED** (ver estados por via en MANIFEST.json y RESULTS.md).

## 1. Objetivo

Documentar el metodo de archivo / texto / catalogo de esta app con evidencia reproducible,
separando observacion, hipotesis y verificacion, sin secretos y sin afirmar lo no probado.

## 2. Muestra: como se obtuvo, hashes

- XAPK de APKPure (version de Google Play 1.7.2); hashes en MANIFEST.json > inputs.
- Sin APK, perfiles reales ni datos de usuarios en este expediente (politica §3: solo hashes publicos).
- Muestras de catalogo y de archivo: ver MANIFEST.json > inputs (las muestras reales de catalogo
  viven en `~/workspace/catalogs/pph/`; aqui solo se referencian por hash).

## 3. Metodo

Una linea Base64 -> XXTEA DELTA 0x2E0BA747 con palabra de longitud (c_01.decryptMain, clave principal) -> JSON {FileName, Version, ReleaseNotes, Servers[], HTTPNetworks[], ...}. Campos cifrados con la clave secundaria XXTEA (c_01.decrypt / ConfigUtil): ServerIP, ServerCloudFront, ServerHTTP, Username, Password, NetworkPayload, SquidProxy, config_url, ghFilename, ProxyHost, sUdpObfs, ovpnCertificate, SSLSNI, Ovpn_Cert. La app compara Version con la preferencia HRL_CONFIG_VERSION (defecto '0') y guarda Servers/HTTPNetworks en SQLite (tabla Harlies_table). Parser.encode/decode: variante Base64 con -18/+18 por byte (c_01$Parser; sin llamadas en el codigo decompilado de esta version). Limpieza JSON 2026-11-15 (regla de Pedro: el JSON de resultado NO lleva APIs de descarga): se quitaron config_url y ghUsername/ghRepoName/ghFilename; se quedan WebUrl, PremiumKey, contactos, IDs de anuncios, credenciales de servidores, payloads, SNI, hosts, puertos y certificados.

### Observacion / hipotesis / verificacion

- **Observacion:** estructuras, clases y constantes leidas del DEX / .so y de las respuestas en vivo
  (ver README de la app para el detalle por clase/funcion).
- **Hipotesis:** el pipeline descrito arriba reproduce el comportamiento de la app.
- **Verificacion:** Catalogo en vivo (2026-11-14, re-verificado 2026-11-15): v6.6, 15 servidores, 7 redes, 0 campos sin abrir; incluido v2.0, 60/14, 0 sin abrir. Self-tests de los scripts operativos: Catalogo 25/25, archivos 17/17 tras la limpieza 2026-11-15 (antes 10/10 y 14 checks).

## 4. Herramientas, por orden, con comandos

1. Extraccion del XAPK en `~/workspace/catalogs/pph/apk/` (+ `xapk/` donde existe).
2. Decompilacion / inspeccion DEX (ver DEPENDENCIES.md para versiones).
3. Emulacion nativa con Unicorn donde se indica (oraculo; no forma parte del runtime).
4. Scripts operativos en `~/workspace/catalogs/pph/` (Python 3 stdlib puro):
   `python3 <Script>.py --self-test` y `python3 <Script>_archivos.py --self-test`.
5. Verificador sanitizado de este expediente: `python3 tools/verify.py` (vectores sinteticos, sin red).

Discrepancias y fallos significativos: ver RESULTS.md y las limitaciones en MANIFEST.json.

## 5. Rutas remotas (sin tokens ni endpoints sensibles)

- Descarga del catalogo: GET con UA okhttp/4.12.0, sin headers extra. Respuesta: una linea Base64, 34156 B. (La URL completa vive solo en el script operativo; aqui no se reproduce.)

La URL completa de descarga y cualquier credencial de acceso viven SOLO en el script operativo
(`~/workspace/catalogs/pph/`) y en `supplied-integrations.json` cuando aplique.
Por la regla de Pedro, los JSON de resultado de catalogo NO llevan las APIs de descarga:
solo datos del catalogo, todo descifrado.

## 6. Auditoria HMAC de conexion (politica §2.2)

La mera presencia de una libreria HMAC no confirma nada. Estados por ambito:

| Ambito | Estado | Evidencia / limite |
|---|---|---|
| catalog_file_integrity | NOT_OBSERVED | XXTEA sin MAC/HMAC observado; la integridad se comprueba por parseo JSON y por el censo de campos (0 sin abrir). |
| catalog_download_auth | NOT_OBSERVED | GET simple con UA okhttp, sin firma observada. |
| crypto_derivation | NOT_OBSERVED | Claves XXTEA fijas en el codigo; no se observo HMAC/KDF en la derivacion. |
| vpn_transport | NOT_OBSERVED | No se observo una conexion VPN en vivo ni MAC del transporte. |
| connection_auth | NOT_OBSERVED | No se trazo autenticacion de conexion. La mera presencia de librerias criptograficas no confirma nada. |

Nunca se guardan valores de claves ni entradas/salidas de hooks en este expediente.

## 7. Alcance real y cambios frente a builds previos

- Lo verificado en vivo es solo para esta version (`1.7.2`, versionCode 75); no se afirma
  compatibilidad con builds previos o posteriores sin prueba.
- Un fixture sintetico demuestra la logica implementada, NO compatibilidad con una version real
  ni conectividad remota: en RESULTS.md se distingue VERIFIED_REAL / VERIFIED_SYNTHETIC /
  REQUIRES_DEVICE / NOT_AUTHORIZED / NETWORK_UNAVAILABLE.

## 8. Archivos de este expediente

- `MANIFEST.json`, `ANALYSIS.md` (este archivo), `REPRODUCE.md`, `RESULTS.md`,
  `DEPENDENCIES.md`, `dependencies.lock.json`
- `tools/verify.py` (verificador sintetico autocontenido) + scripts de investigacion reproducibles
  copiados de `~/workspace/catalogs/pph/work/` (sin secretos; ver notas en REPRODUCE.md)
- `tests/test_method.py` + `tests/fixtures/` (vectores SINTETICOS con claves TEST-ONLY)
