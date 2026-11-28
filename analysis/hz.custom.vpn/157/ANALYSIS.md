# ANALYSIS — Ultra Custom 15.7 (`hz.custom.vpn`, code 157)

- **App:** Ultra Custom 15.7 (versionCode 157)
- **APK analizado:** `Ultra_Custom_15.7_1_9qyw.apks` (46,220,658 bytes),
  SHA-256
  `0d26f70f2e7249b92fa5a4d095ebab029217e22f532d59b089b3ee3ae06a4256`
- **Fecha:** 2026-11-28
- **Alcance:** archivos `.ua` + enlaces `ua://` + suscripción UCS.
  Sin push, sin despliegue desde este trabajo.
- **Veredicto: LOS ARCHIVOS `.ua` ABREN (muestra real Guatemala
  Tigo verificada). SIN CATÁLOGO DE PROVEEDOR (suscripción UCS).**

## 1. Formato `.ua` UAF2 — VERIFIED_REAL

- **Formato:** `!UAF2=:` + base64url(`nonce[12] || AES-256-GCM ct
  || tag[16]`), **AAD literal `!UAF2=:`**.
- **Muestra real:** `Guatemala_Tigo__1__7_fy55.ua` (6,287 B) →
  4,682 B XML, perfil **"Guatemala Tigo"**, `appVersionCode` 157,
  `tunnelType` 12.
- **Claves en este expediente:** la clave UAF2 y la clave de
  máscara NO se guardan aquí. `tools/ultra_custom.py` las carga
  desde `ULTRA_CUSTOM_UAF2_KEY_HEX` / `ULTRA_CUSTOM_MASK_KEY_HEX`
  (o `ULTRA_CUSTOM_TEST_KEYS=1` para las claves sintéticas de los
  tests). Los valores viven solo en el informe del lote.

## 2. Variantes legacy — VERIFIED_SYNTHETIC

- **Legacy:** transformación `libx.so`, `EXA1`/`UAB1` raw-DEFLATE.
- **UAP1:** capa de contraseña — PBKDF2, **210,000 iteraciones**.
- **Bundles:** `UA-BUNDLE-1`.
- **Enlaces:** `ua://`.
- Todas verificadas por round-trip sintético; la muestra real es
  UAF2.

## 3. Catálogo — VERIFIED_ABSENT

- **Sin catálogo de proveedor.** La app obtiene servidores por
  suscripción UCS: JSON firmado **CSS1, ECDSA P-256** sobre
  `b"CloudServers/CSS1\n" + payload`. No hay URL de catálogo del
  proveedor que integrar; la suscripción es del usuario.

## 4. Auditoría HMAC (sección 2.2 de la política)

| Ámbito | Estado | Evidencia |
|---|---|---|
| Archivo/catálogo | NOT_OBSERVED | Integridad por tags AES-256-GCM (AEAD) + firma ECDSA P-256 en los payloads UCS; ningún HMAC |
| Transporte VPN | No observado | Los protocolos se describen en los perfiles; no se trazó ningún handshake |
| Autenticación de conexión | NOT_OBSERVED | Ningún HMAC autoriza el establecimiento de la conexión; las credenciales son usuario/contraseña del perfil. No se intentó ningún login en vivo |

La presencia de AES-GCM + ECDSA prueba integridad/autenticidad
del archivo y de la suscripción, no autenticación de conexión. No
se guardan claves de sesión, tokens ni credenciales reales en este
expediente.
