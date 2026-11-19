# V2Box 6.2.3 (build 88) — corrección del AAD v2 y verificación con archivo real

Estado: **PARTIAL** (v2 kdf "none" VERIFIED_REAL con archivo .v2box
real; v1 real, v2 pbkdf2-sha256 real y v2 ecdh-p256 real siguen
pendientes; catálogo: sin catálogo del vendedor, USER_SUBSCRIPTIONS_ONLY).

## 1. Objetivo

Explicar por qué un archivo `.v2box` v2 real (kdf "none", creado
2026-11-13) daba `TAG_MISMATCH` con el decodificador 6.2.3/88 del
repo, aunque la clave fija era la correcta, y corregirlo.

## 2. Observación

- Archivo real (fuera de Git; SHA-256 y estructura en RESULTS.md):
  sobre JSON `magic "v2box_export"`, `version 2`, header
  `{createdAt, kdf: "none", v: 2}`, nonce 12 B, tag 16 B, ciphertext
  1.164 B, total 1.736 B.
- El decodificador del repo (`decoders/Python/apps/V2Box/
  V2Box_archivos.py`) devolvía `TAG_MISMATCH` (reproducido).
- La clave fija del DEX 6.2.3/88 se re-verificó: los 32 bytes
  ofuscados (XOR 90) están presentes en `classes.dex` (offset
  3734104) y derivan la misma clave del expediente. La clave NO rotó.
- Play sigue en 6.2.3 (AppBrain/Uptodown, última actualización
  2026-10-29); no existe una 6.2.4 ni una 6.3 de Android. La hipótesis
  "clave rotada en versión nueva" queda REFUTADA. El archivo es de
  V2Box (dev.hexasoftware.v2box), no de Pausa VPN: son trabajos
  separados (ver §7).

## 3. Hipótesis y verificación

Batería de hipótesis (herramienta `tools/verify_aad_candidates.py`,
solo estructura/códigos, nunca valores del archivo):

| Hipótesis | Resultado |
| --- | --- |
| Clave fija + AAD = bytes JSON del header (dossier 88) | TAG_MISMATCH |
| Clave fija + AAD vacío | TAG_MISMATCH |
| **Clave fija + AAD = cadena Base64 del header** | **ABRE (JSON válido, 1.164 B)** |
| Clave fija + AAD = header JSON re-serializado (compacto / con espacios / ordenado) | TAG_MISMATCH |
| SHA-256(clave fija), bytes XOR sin desofuscar, clave invertida, HKDF/PBKDF2 derivados | TAG_MISMATCH |

La verificación del tag GCM (128 bits) no admite falsos positivos:
el archivo se cifró con la clave fija v1 y AAD = cadena Base64 del
header.

Corroboración independiente en el propio repo: el decodificador
antiguo `decoders/Python/v2box_export.py` (6.1.2, dg2.java) ya
documenta y usa `cipher.update(encoded_header.encode("ascii"))`,
y `tests/test_v2box_password.py` cifra sus fixtures v2 con AAD =
cadena Base64 del header. El decodificador nuevo 6.2.3 introdujo la
regresión al usar los bytes JSON del header como AAD — una lectura
estática del DEX que nunca se contrastó con un archivo real (su
self-test cifraba y descifraba con el mismo AAD supuesto: circular).

## 4. Cambios frente al build 88 (corrección, no nueva versión)

`decoders/Python/apps/V2Box/V2Box_archivos.py`:
- `_decode_v2`: prueba los AAD en orden — (1) cadena Base64 del
  header (verificado contra archivo real), (2) bytes JSON del header
  (fallback, lectura estática 88, no verificado contra archivo real).
  El resultado incluye `"aad": "header-b64" | "header-bytes"`.
  Aplica a todos los kdf (none, pbkdf2-sha256, ecdh-p256): el AAD es
  propiedad del sobre, no del kdf.
- `_selftest_encrypt_v2`: cifra con AAD = cadena Base64 del header
  (como la app); parámetro `aad_raw_bytes=True` para el fixture del
  fallback.
- Self-test: 7/7 → 9/9 (nuevos: fallback header-bytes; AAD incorrecto
  → TAG_MISMATCH).
- Docstring corregido; `decoders/Python/apps/V2Box/README.md` y
  `manifest.json` (`realSampleVerified: true`) actualizados.

Sin cambios en `cloud/workers/python/v2box_bridge.py` (solo archivos
sin campo `version`; el archivo real tiene `version: 2` y va por
`supplied_bridge` → `V2Box_archivos.py`) ni en
`decoders/Python/v2box_export.py` (ya usaba el AAD correcto).
Sin cambios en `supplied-integrations.json`, `file-formats.json`,
`text-formats.json`, `switches.json`, `decoders.json` ni Android.
Sin bump de CATALOG_VERSION: no se añade catálogo ni proveedor.

## 5. Alcance real

- VERIFIED_REAL: `.v2box` v2 kdf "none" (archivo real 2026-11-13).
- VERIFIED_SYNTHETIC: v1 sin/con contraseña, v2 pbkdf2-sha256,
  v2 ecdh-p256 (con clave de dispositivo de prueba), v2 fallback AAD.
- PENDIENTE: archivo `.v2box` v1 real, archivo v2 pbkdf2 real,
  archivo v2 ecdh-p256 real (necesita la clave privada P-256 del
  dispositivo destinatario), enlace `v2box://locked=` real.
- El archivo real tiene `locked: true`; el mensaje de bloqueo es
  texto visible de la app y NO se reproduce en este expediente.

## 6. Auditoría HMAC (§2.2 de la política)

`connection_authentication`: NOT_OBSERVED. El sobre .v2box usa
AES-256-GCM (autenticación del archivo, no de la conexión VPN): el
tag GCM verifica integridad/autenticidad del archivo exportado con
la clave fija o derivada. No se observó HMAC de transporte ni de
autenticación de conexión en este material; no se afirma ninguno.

## 7. Pausa VPN es otro trabajo (separado)

Pausa VPN = **M Light** (`com.pausatotal.mlight`, 3.1.55, build 80),
app distinta de V2Box. Su catálogo ya está cableado en la rama
(`supplied-integrations.json`, id `m-light`, `catalogState
CONNECTED`) y se re-verificó en vivo 2026-11-19 (ver RESULTS.md).
No se mezclan los diagnósticos: el .v2box es V2Box; Pausa VPN no
tuvo nada que ver con el TAG_MISMATCH.

## 8. Revisión de conexión (heredado)

Registro detallado de la conexión del código aportado:
[ANALYSIS.md](../../platform/supplied-integrations/2026-11-14/ANALYSIS.md).
Fuente y límites originales: [V2Box](../../../decoders/Python/apps/V2Box/README.md).
