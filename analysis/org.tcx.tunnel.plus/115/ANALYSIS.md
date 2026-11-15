# ANALYSIS — TCx Tunnel Plus 1.0.15 (versionCode 115)

Paquete: `org.tcx.tunnel.plus`. Fuente de los hechos: `~/workspace/catalogs/NOTES.md` y `~/workspace/catalogs/tcx/README.md` + `TESTING.md`.
Observado: 2026-11-14/15. Expediente creado 2026-11-14 (Fase 1 del parche de 20 apps, rama `patch/20-apps`).
Estado global del expediente: **PARTIAL** (ver estados por via en MANIFEST.json y RESULTS.md).

## 1. Objetivo

Documentar el metodo de archivo / texto / catalogo de esta app con evidencia reproducible,
separando observacion, hipotesis y verificacion, sin secretos y sin afirmar lo no probado.

## 2. Muestra: como se obtuvo, hashes

- XAPK de APKPure (version de Google Play 1.0.15); hashes en MANIFEST.json > inputs.
- Sin APK, perfiles reales ni datos de usuarios en este expediente (politica §3: solo hashes publicos).
- Muestras de catalogo y de archivo: ver MANIFEST.json > inputs (las muestras reales de catalogo
  viven en `~/workspace/catalogs/tcx/`; aqui solo se referencian por hash).

## 3. Metodo

Body = Base64( XXTEA( AES-128-CBC( JSON ) ) ). AES key = SHA-256(semilla)[:16], IV 16 ceros, PKCS#7. XXTEA delta 0x9E3779B9 estandar (btea, palabra de longitud). Semilla = SHA-256 hex (minusculas) del certificado de firma del APK (mismo desarrollador que el dueno del repo muerto); vive en el global nativo `import` (.bss 0x49ea78, GOT 0x4900d0) y se fija en runtime desde la firma del APK (getSignKey). Verificado contra el nativo con Unicorn (work/emu_verify.py): Python XXTEA == xxtea_encrypt nativo byte a byte; AES encrypt puro == PyCryptodome byte a byte. NO hay transform extra por byte: el helper 0x43b734 es un trampolin a memcpy (PLT ARM). Gotchas de emulacion: FPEXC=0x40000000 para NEON; 4 stubs PLT ARM hay que hookearlos; xxtea_encrypt devuelve bufer malloc en r0 + longitud en *out_len (r3); std::string libc++ de 12 B.

### Observacion / hipotesis / verificacion

- **Observacion:** estructuras, clases y constantes leidas del DEX / .so y de las respuestas en vivo
  (ver README de la app para el detalle por clase/funcion).
- **Hipotesis:** el pipeline descrito arriba reproduce el comportamiento de la app.
- **Verificacion:** Catalogo en vivo MUERTO: HTTP 404 (14 B), re-verificado, exit 2. Vector sintetico y .tcx sintetico abren (este ultimo tambien con renz_decrypt nativo bajo Unicorn). Self-tests de los scripts operativos: Ambos scripts --self-test OK (conteos no registrados en NOTES.md).

## 4. Herramientas, por orden, con comandos

1. Extraccion del XAPK en `~/workspace/catalogs/tcx/apk/` (+ `xapk/` donde existe).
2. Decompilacion / inspeccion DEX (ver DEPENDENCIES.md para versiones).
3. Emulacion nativa con Unicorn donde se indica (oraculo; no forma parte del runtime).
4. Scripts operativos en `~/workspace/catalogs/tcx/` (Python 3 stdlib puro):
   `python3 <Script>.py --self-test` y `python3 <Script>_archivos.py --self-test`.
5. Verificador sanitizado de este expediente: `python3 tools/verify.py` (vectores sinteticos, sin red).

Discrepancias y fallos significativos: ver RESULTS.md y las limitaciones en MANIFEST.json.

## 5. Rutas remotas (sin tokens ni endpoints sensibles)

- Descarga del catalogo: repo GitHub eliminado -> HTTP 404 en vivo (exit 2 del script operativo). Sin red util hoy.

La URL completa de descarga y cualquier credencial de acceso viven SOLO en el script operativo
(`~/workspace/catalogs/tcx/`) y en `supplied-integrations.json` cuando aplique.
Por la regla de Pedro, los JSON de resultado de catalogo NO llevan las APIs de descarga:
solo datos del catalogo, todo descifrado.

## 6. Auditoria HMAC de conexion (politica §2.2)

La mera presencia de una libreria HMAC no confirma nada. Estados por ambito:

| Ambito | Estado | Evidencia / limite |
|---|---|---|
| catalog_file_integrity | NOT_OBSERVED | Body = Base64(XXTEA(AES-128-CBC(JSON))) sin MAC/HMAC observado; la integridad se comprueba por parseo JSON y padding PKCS#7. |
| catalog_download_auth | NOT_OBSERVED | Catalogo muerto (404); no se observo autenticacion de descarga. |
| crypto_derivation | NOT_OBSERVED | Clave AES = SHA-256(semilla)[:16]; semilla = SHA-256 hex del certificado de firma del APK. No se observo HMAC en la derivacion. |
| vpn_transport | NOT_OBSERVED | No se observo una conexion VPN en vivo ni MAC del transporte. |
| connection_auth | NOT_OBSERVED | No se trazo autenticacion de conexion. El anti-tamper por firma del APK no es autenticacion de conexion VPN. |

Nunca se guardan valores de claves ni entradas/salidas de hooks en este expediente.

## 7. Alcance real y cambios frente a builds previos

- Lo verificado en vivo es solo para esta version (`1.0.15`, versionCode 115); no se afirma
  compatibilidad con builds previos o posteriores sin prueba.
- Un fixture sintetico demuestra la logica implementada, NO compatibilidad con una version real
  ni conectividad remota: en RESULTS.md se distingue VERIFIED_REAL / VERIFIED_SYNTHETIC /
  REQUIRES_DEVICE / NOT_AUTHORIZED / NETWORK_UNAVAILABLE.

## 8. Archivos de este expediente

- `MANIFEST.json`, `ANALYSIS.md` (este archivo), `REPRODUCE.md`, `RESULTS.md`,
  `DEPENDENCIES.md`, `dependencies.lock.json`
- `tools/verify.py` (verificador sintetico autocontenido) + scripts de investigacion reproducibles
  copiados de `~/workspace/catalogs/tcx/work/` (sin secretos; ver notas en REPRODUCE.md)
- `tests/test_method.py` + `tests/fixtures/` (vectores SINTETICOS con claves TEST-ONLY)
