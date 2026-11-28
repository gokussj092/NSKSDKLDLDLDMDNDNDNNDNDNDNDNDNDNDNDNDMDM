# ANALYSIS — SNI Tunnel 1.3.7 (`com.asnly.snitunnel`, code 40)

- **App:** SNI Tunnel 1.3.7 (versionCode 40)
- **APK analizado:** `SNI_Tunnel_1.3.7_0_1l9k.apks` (25,177,383 bytes;
  SHA-256 no registrado en el informe del lote)
- **Fecha:** 2026-11-28
- **Alcance:** enlaces v2rc/v2rcloud + nube `snicfg.asnly.net` +
  enlaces estándar. Sin push, sin despliegue desde este trabajo.
- **Veredicto: PARCIAL — SIN CATÁLOGO (cliente BYOC). La capa
  externa del enlace v2rc "SOMBRE" SÍ se descifró; la config
  interior NO (contraseña desconocida, enlace caducado). La nube
  `snicfg.asnly.net` está verificada en vivo.**

> SNI Tunnel es Flutter/Dart + Kotlin + núcleo Xray en Go. No es
> un proveedor de servidores: el usuario trae sus propias
> configuraciones (BYOC). Su formato propio es el enlace de
> compartición v2rc (sellado ECDH + HKDF) y el relay en la nube
> `snicfg.asnly.net`.

## 1. Catálogo — VERIFIED_ABSENT

- **Sin catálogo.** La app no descarga ninguna lista de
  servidores. El usuario importa sus propias configuraciones
  (enlaces estándar o enlaces v2rc/v2rcloud).

## 2. Enlace v2rc "SOMBRE" — PARTIAL

- **Versión 2**, `expiresAt` 817513200 = 2026-11-27T23:00:00Z
  (**caducado**), `deviceIDHash` `cf4ee69ba23d15b96c5e4ade` = registro
  abierto `v2rc-app-open-v1`, `ephemeralPub` 64 B (P-256),
  ciphertext 968 B (ChaCha20-Poly1305).
- **Capa externa — descifrada:** ECDH P-256 + HKDF-SHA256, info
  `v2rc-seal-v1` + clave pública del destinatario, salt =
  `ephemeralPub`.
- **Capa interior — NO descifrada:** sobre de contraseña
  PBKDF2-HMAC-SHA256, salt 16 B, **120,000 iteraciones**,
  contraseña desconocida.
- **Semilla de clave de dispositivo:**
  `"sni-tunnel-device-id-v2|<package>|<ANDROID_ID>"` — el
  `ANDROID_ID` es específico del dispositivo y nunca se guarda
  aquí.
- **Claves de app en este expediente:** el material de clave
  desofuscado NO se guarda aquí. `tools/sni_tunnel.py` lo carga
  desde `SNI_TUNNEL_APP_PRIV_B64` / `SNI_TUNNEL_APP_PUB_B64`. Los
  valores viven solo en el informe del lote.

## 3. Nube `snicfg.asnly.net` — VERIFIED_REAL

- **Relay:** `https://snicfg.asnly.net/v1/configs`, verificado en
  vivo: crear → reclamar → abrir; un segundo reclamo devuelve
  **410 (agotado)**. Es un relay de compartición (un solo uso por
  defecto), no un catálogo.

## 4. Enlaces estándar — VERIFIED_SYNTHETIC

- Esquemas `vmess://`, `vless://`, `trojan://`, `ss://`,
  `hysteria2://`, `hy2://`, `tuic://`, `socks://`, `ssh://` +
  `v2rc://`, `v2rcloud://`, `snitunnel://`. Round-trip verificado
  con enlaces sintéticos.
- **Sin formato de archivo propio.** No hay `.sks`.

## 5. Auditoría HMAC (sección 2.2 de la política)

| Ámbito | Estado | Evidencia |
|---|---|---|
| Archivo/catálogo | NOT_OBSERVED | Sin catálogo ni archivo propio; el sobre v2rc usa tag ChaCha20-Poly1305 (AEAD), no HMAC |
| Transporte VPN | No observado | Los protocolos se describen en las configuraciones; no se trazó ningún handshake |
| Autenticación de conexión | NOT_OBSERVED | Ningún HMAC autoriza el establecimiento de la conexión. **HKDF-SHA256 es derivación de clave basada en HMAC, no autenticación de conexión** — se documenta aquí como derivación, no como auth |

La presencia de HKDF/ChaCha20-Poly1305 prueba integridad del
sobre, no autenticación de conexión. No se guardan claves de
sesión, tokens ni credenciales reales en este expediente.
