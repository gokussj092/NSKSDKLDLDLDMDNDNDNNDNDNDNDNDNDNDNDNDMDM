# ANALYSIS — VLX Tunnel VPN v1.11.24.2 (`dev.jx.clickconnect`, code 19)

- **App:** VLX Tunnel VPN v1.11.24.2 (versionCode 19)
- **APK analizado:** `VLX_Tunnel_VPN_v1.11.24.2_2_4bta.apks`
  (43,082,718 bytes; SHA-256 no registrado en el informe del lote)
- **Fecha:** 2026-11-28
- **Alcance:** catálogo en vivo + archivos `.vlx` + enlaces de texto.
  Sin push, sin despliegue desde este trabajo.
- **Veredicto: PARCIAL — el catálogo en vivo y los archivos `.vlx`
  SÍ abren (Version 23.794, 16 servidores, 4,549/4,549 campos).
  Tres fuentes nuevas NO se descifraron y NO se integran:
  `configfile.json`, el blob de `/api/vlx/` y `/api/vlxnew/`.**

> Este expediente continúa el de v14 (`analysis/dev.jx.clickconnect/18/`,
> VERIFIED). La criptografía del catálogo y de los archivos NO cambió
> (Argon2id + AES-256-GCM, sin letra de marcador), pero el nuevo
> `libgojni.so` ya no guarda las claves en `.rodata` y aparecieron
> tres fuentes cifradas nuevas que no abren con las claves vivas.

## 1. Catálogo en vivo — VERIFIED_REAL

- **Observación:** `GET https://strongteam.co/api/vlx/v1/` con
  `User-Agent: VLX Tunnel VPN` obligatorio (sin esa UA la petición
  no sirve el catálogo). Respuesta JSON con campo `data` en Base64.
- **Verificación en vivo 2026-11-28:** Version **23.794**, **16
  servidores**, **731 redes**, **621 payloads**, **4,549/4,549
  sobres de campo descifrados, 0 fallos**.
- **Formato del sobre:** Base64, con la estructura del envoltorio
  Argon2id + AES-256-GCM: salt (16 B) + nonce (12 B) + ciphertext +
  tag (16 B). Derivación: **Argon2id, t=3, m=8192 KiB, threads=1**,
  salida 32 B; AES-256-GCM con la clave derivada. **Sin letra de
  marcador** (a diferencia de otras apps de la familia: la clave se
  elige por contexto — clave viva para el catálogo en vivo, clave de
  campo para los campos y el asset incluido).
- **Claves en este expediente:** las dos claves de formato NO se
  guardan aquí. `tools/VLX_Tunnel_VPN.py` las carga desde
  `VLX_KEY_LIVE` (catálogo en vivo) y `VLX_KEY_FIELD` (campos +
  asset incluido); `VLX_Tunnel_VPN_archivos.py` usa `VLX_KEY_FILE`
  para archivos `.vlx`. Los valores viven solo en el informe del
  lote. En los tests, `--self-test` usa una contraseña sintética
  (`TEST_PASSWORD`) cuando no hay clave configurada.
- **Las claves ya no están en el nuevo `libgojni.so`:** el `.rodata`
  del nuevo `libgojni.so` no contiene las claves II/FIELD; las
  claves siguen vivas (el catálogo en vivo abre con ellas), así que
  hay que conservarlas por variables de entorno al integrar. La vía
  dinámica con qemu está bloqueada (layout TLS bionic vs glibc).

## 2. Archivos `.vlx` — VERIFIED_REAL (muestra del lote 18)

- **Formato:** `VLX1|<flags>|<payload>`, bit 0 = sobre AES-256-GCM
  (misma derivación Argon2id). La muestra `muestra.vlx` del lote 18
  re-verificada: abre. No se suministró una exportación nueva de
  v1.11.24.2.
- **Enlaces:** `vmess://`, `vless://`, `trojan://`, `ss://` (formas
  estándar). Sin esquema propio `vlx://`.

## 3. Lo que NO se descifró — NO integrado (PARTIAL)

| Fuente | Tamaño | Qué se intentó | Resultado |
|---|---|---|---|
| `configfile.json` (asset incluido) | 680,700 B | claves viva y de campo; barrido de claves candidatas | NO abre; los 20 servidores de muestra dentro de él siguen sin descifrar |
| Blob de `/api/vlx/` | 793,236 B Base64 | claves viva y de campo | Tiene la estructura de bytes del sobre pero no abre con ninguna de las dos |
| `/api/vlxnew/` (POST) | — | — | Devuelve `Invalid hash`; el formato del hash no está determinado |

Estas tres fuentes quedan fuera de la integración. Si en el futuro
se determina su clave/formato, se documentarán en un expediente
nuevo (no se inventa nada aquí).

## 4. Splits y librerías nativas

- `base.apk`: SIN librerías nativas; assets: `api` (catálogo
  incluido), `configfile.json` (nuevo, 680,700 B).
- `split_config.arm64_v8a.apk`: TODAS las librerías nativas,
  incluido el nuevo `libgojni.so` (núcleo Xray). Ninguna librería
  interviene en el descifrado del catálogo más allá de `libgojni.so`
  (que ya no guarda las claves en `.rodata`).
- Icono 512×512 (bytes distintos al de v14).

## 5. Auditoría HMAC (sección 2.2 de la política)

| Ámbito | Estado | Evidencia |
|---|---|---|
| Archivo/catálogo | NOT_OBSERVED | Integridad por tags AES-256-GCM (AEAD), no por HMAC |
| Transporte VPN | No observado | Los protocolos se describen en el catálogo; no se trazó ningún handshake |
| Autenticación de conexión | NOT_OBSERVED | Ningún HMAC autoriza el establecimiento de la conexión; las credenciales son usuario/contraseña del catálogo. No se intentó ningún login en vivo |

La presencia de Argon2id + AES-GCM prueba integridad del sobre,
no autenticación de conexión. No se guardan claves de sesión,
tokens ni credenciales reales en este expediente.
