# ANALYSIS — Surya Tunnel 1.6 (`com.suryavpn.tunnel`, code 6)

- **App:** Surya Tunnel 1.6 (versionCode 6; el manifiesto dice 1.6,
  no 1.6.3)
- **APK analizado:** `SuryaTunnel_1.6_3_jqle.apks` (21,712,198 bytes;
  SHA-256 no registrado en el informe del lote)
- **Fecha:** 2026-11-28
- **Alcance:** archivos `.st` + enlaces SVPN. Sin push, sin
  despliegue desde este trabajo.
- **Veredicto: LOS ARCHIVOS `.st` ABREN (muestra real V3 descifrada
  completa). SIN CATÁLOGO EN VIVO.**

> El formato `.st` de Surya es DISTINTO al `.st` de Sentinel Tunnel:
> Surya usa magia `SPN1` (AES-GCM con clave derivada de una
> etiqueta), Sentinel usa magia `STCF` (XOR + HMAC). No confundirlos.

## 1. Formato `.st` SPN1 — VERIFIED_REAL (muestra V3)

- **V1:** AES-256-CBC, sin magia (detección por longitud/estructura).
- **V2:** AES-256-GCM, clave = SHA-256 de la etiqueta de config.
- **V3:** AES-256-GCM, clave = PBKDF2-HmacSHA256 de la etiqueta,
  salt, **150,000 iteraciones**, salida 32 B.
- **SPW1:** archivos con contraseña — PBKDF2, **120,000
  iteraciones**.
- **Perfiles `_locked`:** perfiles con claves cortas (claves
  truncadas/derivadas de forma distinta; documentadas en el
  decoder).
- **Muestra real:** `Robi_Airtel_Fre_Internet_Slow_Dns_V4_2_261w.st`
  (2,301 B) descifrada completa: 1 perfil, `LOCK_ALL`, `modeIndex`
  0 (SSH), SlowDNS activado.
- **Etiqueta de config en este expediente:** la etiqueta NO se
  guarda aquí. `tools/surya_tunnel.py` la carga desde
  `SURYA_CONFIG_LABEL` (o `SURYA_TEST_LABEL=1` para la etiqueta
  sintética de los tests). El valor vive solo en el informe del
  lote.

## 2. Enlaces SVPN1–SVPN4 — VERIFIED_SYNTHETIC

- Esquemas de texto `SVPN1`–`SVPN4` (round-trip verificado con
  enlaces sintéticos). Sin muestra real de enlace.

## 3. Catálogo — VERIFIED_ABSENT

- **Sin catálogo en vivo.** La URL de Cloud Sync la pega el
  usuario; por defecto está vacía. No hay catálogo de proveedor
  que integrar.

## 4. Auditoría HMAC (sección 2.2 de la política)

| Ámbito | Estado | Evidencia |
|---|---|---|
| Archivo/catálogo | NOT_OBSERVED | Integridad por tags AES-256-GCM (AEAD), no por HMAC; sin catálogo |
| Transporte VPN | No observado | Los protocolos se describen en los perfiles; no se trazó ningún handshake |
| Autenticación de conexión | NOT_OBSERVED | Ningún HMAC autoriza el establecimiento de la conexión; las credenciales son usuario/contraseña del perfil. No se intentó ningún login en vivo |

La presencia de AES-GCM prueba integridad del archivo, no
autenticación de conexión. No se guardan claves de sesión, tokens
ni credenciales reales en este expediente.
