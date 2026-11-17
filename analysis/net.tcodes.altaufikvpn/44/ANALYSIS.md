# ALTAUFIK VPN 5.01 — ANALYSIS

- Paquete: `net.tcodes.altaufikvpn` · versionCode: 44 · versionName: `5.01`
- Observado: 2026-11-17 · Estado del expediente: **VERIFIED** (catálogo VIP)
- Muestra: `ALTAUFIK_VPN_5.01_0_m7hy.apks` (34.116.543 B, SHA-256
  `93c7ca977f38a7d5f8300a99dae4db04f2ad574e001601745d64f077ff6d33d3`;
  base.apk + splits arm64/es/xhdpi). El .apks no se guarda en Git.

## Objetivo

Documentar el método de descifrado del catálogo de esta app para
SP-DECODE, con evidencia reproducible y sin secretos, como paso previo
a su integración.

## Cómo se obtuvo la muestra

APK público (.apks) verificado por SHA-256 según README de origen.
`jadx` completo se quedó sin memoria (OOM al 64%, 6 GB); la
verificación se hizo con `strings` + desensamblado dirigido con
androguard de `MainActivity.L`, `F2/n.doInBackground` y `M2/d.a`, más
la prueba en vivo de ambos endpoints.

## Método

Familia tcodes (misma que 24clan / EDOZ): mismo contenedor OpenSSL
Salted__, mismo SQLite `system.db` / `tcodes_table`, mismo cliente
Apache `DefaultHttpClient`. Descarga: `MainActivity.L(Z Z)` → `F2/n`
(AsyncTask) → `HttpGet` sobre la URL tal cual, sin cabeceras propias,
sin parámetros, sin token, sin sesión; el stack envía implícitamente
`User-Agent: Apache-HttpClient/UNAVAILABLE (java 1.4)`. El segundo
booleano es la preferencia `use_vip` (leída en `onResume`): `false` →
URL gratis, `true` → URL VIP. El cuerpo se lee con
`InputStreamReader(content, "iso-8859-1")` y `readLine()` concatenado.
Si la petición falla, devuelve la cadena `"error"`.

Descifrado (`M2/d.a`): Base64 → contenedor OpenSSL `Salted__` (salt de
8 B) → EVP_BytesToKey/MD5, 1 iteración, contraseña de formato
`mtscrypt` (`M2/d.<clinit>`, no credencial de cuenta):
`D1 = MD5("" + "mtscrypt" + salt)`, `D2 = MD5(D1 + "mtscrypt" + salt)`,
`D3 = MD5(D2 + "mtscrypt" + salt)`, `key = D1||D2` (32 B), `iv = D3`
(16 B) → AES-256-CBC/PKCS#7 → JSON UTF-8. Si OpenSSL no puede
descifrar, `M2/d.a` devuelve la cadena tal cual (el script admite
también JSON sin cifrar que empiece por `{`). El JSON en vivo trae
caracteres de control crudos dentro de valores de texto; `org.json`
los tolera, así que el script parsea con `strict=False`.

El callback (`D2/k`) compara `Version` con la versión guardada: si la
remota es mayor, ofrece la actualización y guarda la respuesta cifrada
tal cual en SQLite (`system.db`, tabla `tcodes_table`, ID 1 = gratis /
ID 2 = VIP). En el primer arranque, `MainActivity` copia
`assets/defconf` (gratis) y `assets/vip_defconf` (VIP) a esa misma
tabla si está vacía. Ambos descifran con `mtscrypt`.

El dominio es `24clanvpn.com`: ALTAUFIK comparte la infraestructura
de actualización de 24clan (mismo builder tcodes), con rutas propias
por app.

## Catálogo en vivo (verificado 2026-11-17)

| Fuente | Version | Servers | Tweaks | Tweaks con Payload |
| --- | --- | --- | --- | --- |
| Remoto VIP (`--vip --url`) | **9.5** | **7** | **1458** | **1343** |
| Remoto gratis (`--url`) | — | — | — | **MUERTO: HTTP 200, cuerpo de 2 bytes (`ff`), `Last-Modified: Fri, 06 Oct 2023`. No descifra; FORMAT_ERROR.** |
| `assets/defconf` (gratis integrado) | 9.6 | 4 | 1486 | 1386 |
| `assets/vip_defconf` (VIP integrado) | 8.3 | 7 | 1568 | 1447 |

El catálogo en vivo que abre es el VIP (v9.5). El gratis en vivo está
muerto desde al menos 2023; la app cae al integrado (v9.6, que es
incluso más nuevo que el VIP en vivo). `live.json` es el VIP en vivo;
`bundled_free.json` es el gratis integrado descifrado. `live_probe.json`
documenta ambas respuestas HTTP con SHA-256 y `Last-Modified`.

Campos de servidor (todo en claro): `Name`, `Flag`, `SSHHost`,
`PublicKey` (hex), `NameServer`, `OpenVPNHost`, `HUDPHost`, `V2Ray`
(enlace `vmess://` estándar, ya cubierto por SP-DECODE), `UDPPort`,
`SSHPort`, `SSLPort`, `DropBear`, `ProxyPort`, `UDPCertificate`
(Base64 de un texto de certificado OpenVPN legible, no cifrado).
Campos de tweak (todo en claro): `Flag`, `CustomProxy`, `Port`,
`Country`, `Direct`, `Websocket`, `DNS`, `Bug`, `DNSAddress`, `UDP`,
`HUDP`, `Name`, `Info`, `Payload`, `ProxyHost`, `ProxyPort`, `SSL`,
`UseInbuiltUserPass`. El JSON no trae claves de API de descarga.

## Qué quedó sin descifrar

Nada: los dos catálogos integrados y el VIP en vivo descifran
completos con `mtscrypt`. No hay valores cifrados dentro del JSON
(0 tweaks con payload solo-Base64; `UDPCertificate` es Base64 de texto
legible). El único hueco es el endpoint gratis en vivo, que no
devuelve catálogo (cuerpo `ff`).

## Archivos y texto

Sin formato propio de archivo ni esquema de texto propio (verificado
en el manifest: sin intent-filter `ACTION_VIEW` para archivos ni
esquema URI propio; sin código de importación/exportación de perfiles).
La única importación es la genérica de OpenVPN (`.ovpn`/`.conf`, de la
librería OpenVPN, no un formato propio). Los servidores/tweaks
personalizados se crean a mano en la UI y se guardan en `system.db`.
Solo los enlaces estándar `vmess://` dentro del JSON de servidores,
que SP-DECODE ya cubre.

## Auditoría HMAC

- Integridad de archivos: NOT_OBSERVED — no hay archivos propios.
- Integridad de catálogos: NOT_OBSERVED — sin HMAC ni MAC; el
  contenedor OpenSSL Salted__ solo lleva salt; la integridad la da el
  padding PKCS#7 + el parseo JSON estructural.
- Derivación criptográfica: NOT_OBSERVED — EVP_BytesToKey/MD5, no HMAC.
- Transporte VPN: NOT_OBSERVED — no se revisó el transporte VPN.
- Autenticación de conexión: NOT_OBSERVED — la descarga es GET sin
  autenticación. La mera presencia de MD5 no demuestra HMAC.

## Herramientas, por orden

1. Extracción del .apks (base + splits de ABI/idioma/dpi).
2. `strings` + androguard (DEX) para localizar las clases de red y
   descifrado.
3. Construcción del script operativo (PyCryptodome para AES) y prueba
   contra descarga real y contra los assets incluidos.
4. Verificación de la regla SP-DECODE 2026-11-15: el JSON de resultado
   lleva solo los datos del catálogo, todo descifrado; las APIs de
   descarga NO van en el resultado.
