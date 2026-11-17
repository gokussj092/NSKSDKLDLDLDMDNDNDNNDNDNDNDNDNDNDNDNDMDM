# DeepTune-VPN v8 — ANALYSIS

Paquete `tun.deep.vpn`, versionCode 8, versionName `v8` (verificado
con androguard 4.1.4 sobre el `base.apk` extraído del `.apks`).
Estado global: **PARTIAL** (catálogo abre en vivo con valores
parciales; archivos VERIFIED contra el asset empaquetado; sin
esquema propio de texto).

## 1. Método de catálogo (verificado en vivo)

- Descarga: `GET` del `deep3.txt` en el dominio del operador, con
  cabecera `User-Agent: DeepTune-VPN`. La respuesta se trunca detrás
  de Cloudflare con `urllib`; el script usa `requests` si está
  disponible (con respaldo a `urllib`) y reintenta hasta 3 veces por
  transporte si el descifrado falla (una descarga truncada no pasa
  la verificación AES-GCM).
- Archivo en vivo: se descarta el byte en el índice 3 del texto,
  luego Base64. Layout: Base64(`salt[0:16] || nonce[16:28] ||
  ciphertext[28:]`), Argon2id (t=3, m=8192 KiB, p=1, keyLen=32) +
  AES-256-GCM, AAD = salt. Contraseña del archivo en vivo distinta
  de la de campos (ambas extraídas del APK v8, `libgojni.so` —
  AndroidLibXrayLite).
- Campos dentro del JSON: misma construcción (Argon2id + AES-256-GCM,
  AAD = salt), contraseña de campos. Si un valor no descifra con
  ninguna de las dos contraseñas, es texto plano y se deja como está
  (igual que la app).
- Resultado vivo (re-corrida 2026-11-17): **v3.12, 6 servidores, 102
  redes** (la muestra entregada era v3.11, 101 redes; la única
  diferencia es la versión y UNA red nueva — `🇸🇦 KSA | Mobily FR 10%
  WORK ✈` —; los 6 servidores son idénticos campo a campo).
  Descarga + descifrado completos en **17,6 s** en esta VM (tope del
  catálogo: 120 s).
- El JSON de resultado lleva SOLO los datos del catálogo, todo
  descifrado; las APIs de descarga NO van en el resultado (regla del
  propietario, 2026-11-15). Verificado: el JSON no contiene la ruta
  de descarga ni el nombre del archivo remoto; las únicas URLs son
  datos del catálogo (enlace de Telegram, plantillas de payload con
  URLs de operadoras).

## 2. Archivos (verificado contra el asset empaquetado)

- `deeptune_vpn.py` decodifica: `configfile.json` del APK (Base64
  directo, contraseña de campos), `deep3.txt` descargado (descarta
  el byte 3, contraseña de archivo) y JSON ya descifrado (solo
  descifra los campos que sigan cifrados).
- Asset empaquetado `work/bundled.json` (configfile del APK): abre →
  **v1.01, 9 servidores, 111 redes** en 5,1 s.
- La app NO tiene extensión de archivo propia ni esquema de enlace
  propio. Importa enlaces estándar VLESS/VMess/trojan/ss y JSON de
  configuración Sandok; esos ya los decodifica SP-DECODE.

## 3. Valores que NO descifran del todo (entregados tal cual)

### 3.1 Fracasos reales: 12 valores (2 contraseñas probadas, 0 aciertos)

En el catálogo vivo v3.12, estos valores de la lista de campos del
script siguen siendo sobres Base64 tras intentar ambas contraseñas:

| Servidores | Campos que no abren |
|---|---|
| `🟢 Global Server Online--01`, `--02`, `-- SSH` (3 servidores OVPN/SSH) | `SlowDNSHost`, `SlowDNSKey`, `V2rayUUID` (9 valores) |
| `Global UDP`, `Dynamic Dns 01`, `🌥️ Cloudflare Dns ( 01)` (3 servidores) | `SlowDNSKey` (3 valores, un mismo cifrado compartido distinto del de los 3 anteriores) |

Total: **12 valores**. Los 9 de los 3 servidores OVPN/SSH son los
"9 valores parciales" ya reportados en el análisis original; los 3
`SlowDNSKey` restantes (otro cifrado compartido) no se habían contado
por separado. Misma clase de límite que Bee/MM Tunnel: sobres con
clave no recuperada del APK. Se entregan tal cual, sin inventar nada.
(Nota: `CustomCertificate` en esos 3 servidores es texto plano
—config OpenVPN en claro—, no un fracaso.)

### 3.2 Laguna de la lista de campos: 48 valores que SÍ descifran

Estos valores descifran correctamente con las contraseñas
existentes (verificado valor por valor con `decrypt_field` del
propio script), pero **no están en las listas `SERVER_FIELDS` /
`NETWORK_FIELDS`** de los scripts, así que el resultado los deja
cifrados:

- Servidores (24 valores): `ServerIPHost`, `UDP_obfs`, `UDP_user`,
  `H2pass` en los 6 servidores. Ejemplo verificado: `ServerIPHost`
  de `Global Server Online--01` descifra a `sm.mtmtun.com` (un
  hostname, claramente destinado a descifrarse). `UDP_obfs` /
  `UDP_user` / `H2pass` descifran a una capa de tokens en Base64
  (forma legítima de texto plano para claves/tokens).
- Redes (24 valores): `BugDNS` en 24 de las 102 redes (las otras 78
  ya son texto plano). Todos descifran a `8.8.8.8`.

Esto es una laguna de la lista de campos del script, NO un fallo
criptográfico. Ampliar `SERVER_FIELDS` con `ServerIPHost`,
`UDP_obfs`, `UDP_user`, `H2pass` y `NETWORK_FIELDS` con `BugDNS`
es un cambio del script operativo y queda como decisión pendiente
(ver REPORT.md, pregunta abierta 2). NO se hizo en silencio en esta
entrega: los scripts en staging son byte-idénticos a los entregados.

## 4. Dependencia que falta en el worker (bloqueante)

Los scripts importan `cryptography.hazmat.primitives.ciphers.aead`
(`AESGCM`) en el nivel superior, sin fallback. `cryptography` **NO
está en el `requirements.txt` raíz del repo**: verificado con un venv
limpio que instala solo ese `requirements.txt` — `import cryptography`
falla con `ModuleNotFoundError`, mientras `argon2`, `Crypto` y
`requests` importan bien. Los demás usos de `cryptography` en el repo
son fallbacks perezosos tras `pycryptodome` (p. ej. `TLS.py`,
`EV2RAY.py`, `V2Box_archivos.py`); DeepTune es el único que la exige
en el nivel superior. Sin añadir `cryptography` al
`requirements.txt` (y reconstruir la imagen del worker), el módulo
falla con `ImportError` al importarse. Ver REPORT.md, spec §4.

## 5. Auditoría HMAC

- Integridad de archivos: tags AES-256-GCM (AEAD), no HMAC.
  Estado: NOT_OBSERVED.
- Integridad de catálogos: misma construcción AEAD; no se observó
  HMAC. Estado: NOT_OBSERVED.
- Derivación criptográfica: Argon2id; sin HMAC en la derivación.
  Estado: NOT_OBSERVED.
- Transporte VPN: no se revisó el transporte VPN de esta app.
  Estado: NOT_OBSERVED.
- Autenticación al establecer la conexión: no se observó HMAC de
  autenticación de conexión. Estado: NOT_OBSERVED.

La presencia de una biblioteca HMAC no demuestra su uso; aquí no se
observó HMAC en ningún propósito.

## 6. Límites y pendientes

- 12 valores de campo sin abrir (clave no recuperada del APK).
- ~~48 valores no intentados por las listas de campos~~ — **RESUELTO por el coordinador 2026-11-17** (listas ampliadas y verificadas en vivo; ver REPORT.md).
- `cryptography` fuera del `requirements.txt` del worker.
- Broker sin reintentos ante truncado de Cloudflare (el script
  reintenta; el broker supplied no).
- Icono: reescalado 192×192 → 512×512 (el origen del APK es 192×192).
