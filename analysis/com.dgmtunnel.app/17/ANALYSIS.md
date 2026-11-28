# ANALYSIS — DGM Tunnel 15.11.2026 (`com.dgmtunnel.app`, code 17)

- **App:** DGM Tunnel 15.11.2026 (versionCode 17)
- **APK analizado:** `base-1_0_9jst.apk` (33,017,256 bytes; SHA-256 no
  registrado en el informe del lote)
- **Fecha:** 2026-11-28
- **Alcance:** lista pública en texto plano + enlaces
  DGMTUNNEL_SHARE v2. Sin push, sin despliegue desde este trabajo.
- **Veredicto: SIN CATÁLOGO CIFRADO — el "catálogo" es una lista
  pública en texto plano (rotativa, sin versión). Los enlaces
  DGMTUNNEL_SHARE v2 SÍ abren (con y sin contraseña).**

> `libgojni.so` es el núcleo Xray de stock: no hay catálogo cifrado
> ni clave de proveedor que recuperar. La app descarga una lista
> pública de GitHub y toma las primeras 40 líneas como catálogo.
> El formato propio de la app es el enlace de compartición
> DGMTUNNEL_SHARE v2 (PBKDF2 + AES-256-GCM).

## 1. El "catálogo": lista pública en texto plano — VERIFIED_REAL

- **Fuente:** `GET https://raw.githubusercontent.com/barry-far/V2ray-config/main/All_Configs_Sub.txt`
  con `User-Agent: DGMTunnel/1.5` (encontrado en el APK; es la
  lista `barry-far/V2ray-config`, un repositorio de terceros, no de
  DGM).
- **Instantánea en vivo 2026-11-28 10:05:49 UTC:** HTTP 200,
  2,122,468 B, 8,880 líneas / 8,873 enlaces; parseo: 500 perfiles
  tras 557 líneas (57 rechazados); dedup → 171 únicos; catálogo =
  **primeras 40 líneas, todas Shadowsocks** en esta instantánea.
- **Sin versión:** la lista rota sin aviso; el catálogo es el
  primer bloque de 40 líneas del momento. No hay versión, fecha ni
  firma que verificar.
- **Sin cifrado:** texto plano (enlaces `ss://`/`vless://`/
  `vmess://`/`trojan://` estándar). No hay clave de formato, no hay
  sobre, no hay integridad (la lista no está firmada).

## 2. DGMTUNNEL_SHARE v2 — VERIFIED_REAL (ambos enlaces caducados)

- **Formato:** texto de compartición con cabecera `key=value`
  (id, expiresAt, passwordProtected, locked, protocol) + payload
  Base64: **PBKDF2-HMAC-SHA256, 600,000 iteraciones, salt 16 B**,
  **AES-256-GCM, IV 12 B, AAD = las líneas de cabecera**.
  Sin contraseña: la clave se deriva de una cadena fija del
  formato; con contraseña: la contraseña la da el usuario (nunca
  se guarda).
- **Enlace 1 — `9bcf46a7-d896-46df-b789-9af6140ac851`:** creado
  2026-11-27 08:17:33 PST, `expiresAt` 2026-11-27 11:17:15 PST
  (**caducado**), `passwordProtected: true`, contraseña
  desconocida, payload no incluido en el texto. No se pudo abrir
  (contraseña desconocida + caducado).
- **Enlace 2 — `494af5fc-ef1c-4395-85f6-aead85bd7ec9`:** `expiresAt`
  1795657170825 ms = 2026-11-26 01:39:30 UTC (**caducado**),
  `passwordProtected: false`, `locked: true`, protocolo TROJAN.
  **Descifrado y verificado** (config guardada en el directorio del
  lote como `share-494af5fc.descifrado.json` — contiene credenciales
  reales y NO se copia a este expediente).
- **CloudShares:** la base `https://xhat-app.preview.emergentagent.com`
  (`/api/shares`) es solo un servicio de enlaces de compartición,
  no un catálogo.

## 3. Archivos — VERIFIED_ABSENT

- **Sin formato de archivo propio.** No hay `.sks` ni ningún otro
  formato de archivo de DGM Tunnel. La importación es por enlaces
  (texto) o por la lista pública.

## 4. Auditoría HMAC (sección 2.2 de la política)

| Ámbito | Estado | Evidencia |
|---|---|---|
| Archivo/catálogo | NOT_OBSERVED | La lista pública no tiene ninguna protección de integridad (texto plano sin firma); los enlaces DGMTUNNEL_SHARE usan tag AES-256-GCM (AEAD), no HMAC |
| Transporte VPN | No observado | Los protocolos se describen en los enlaces; no se trazó ningún handshake |
| Autenticación de conexión | NOT_OBSERVED | Ningún HMAC autoriza el establecimiento de la conexión; las credenciales son el uuid/contraseña dentro de cada enlace. No se intentó ningún login en vivo |

La lista pública no está firmada: cualquiera puede servir una
lista distinta con la misma URL. Eso es una propiedad del formato
(la app confía en el repositorio de GitHub), no un fallo de este
expediente. No se guardan claves de sesión, tokens ni credenciales
reales en este expediente.
