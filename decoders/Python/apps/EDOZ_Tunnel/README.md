# EDOZ Tunnel — catálogo (SP-DECODE)

App analizada: **Edoztunnel - Unlimited VPN**, paquete
**`net.androidtechvilla.edoztunnel`**, versión **3.7**, build **28**
(`versionCode=28`, `versionName=3.7`, minSdk 21, targetSdk 34).
APK: `apk/Edoztunnel_3.7.apk` (83.324.631 bytes, SHA-256
`4fe8dd1b7a19d6803fb4ba4337d9214c3ad6b7c660010345aa30fe26649a4b0e`).
Alcance: solo catálogo. No se modificó el repo SP-DECODE ni se subió
nada a Git. No se imprimen ni se guardan en este documento valores
descifrados (contraseñas, claves, hosts): solo recuentos y nombres de
campos.

Sin cobertura previa en el repo: `decoders/Python/apps/` no tiene
ninguna carpeta EDOZ / technore / androidtechvilla (solo
`24clan_VPN_Green`, otra app). El método es de la misma familia tcodes
que 24clan, pero con otra contraseña de formato.

## Método exacto (verificado en este APK)

### Descarga del catálogo remoto

- **Endpoint:** `GET https://raw.githubusercontent.com/chrisrepair/Updates/main/Edoztunnnel%20lite%20V7%202024`
- **Disparador:** `MainActivity.V0(boolean, boolean)` → `new l5.h(this,
  z11 ? p5.d.f8802d : p5.d.f8801c, new b0(...)).execute(...)`.
  Con `use_vip` en false usa `p5.d.c` (la URL de arriba); con VIP
  usaría `p5.d.d`, que está **vacío por defecto** en este build.
- **Petición (`l5.h.doInBackground`):** Apache `DefaultHttpClient`,
  `HttpGet` sobre la URL tal cual. **Sin cabeceras propias, sin
  parámetros, sin token, sin sesión y sin autenticación.** El stack
  envía implícitamente su `User-Agent` por defecto
  (`Apache-HttpClient/UNAVAILABLE (java 1.4)`); el script replica ese
  valor. El cuerpo se lee con `InputStreamReader(content,
  "iso-8859-1")` y `readLine()` concatenado (sin saltos de línea).
  Si la petición falla, devuelve la cadena `"error"`.
- El servidor responde igual con cualquier User-Agent (verificado en
  vivo con el UA de Dalvik y con curl).

### Descifrado y validación (`p5.f.a`, `MainActivity$b0.a`)

1. La respuesta es texto Base64 estándar.
2. `Base64.decode(respuesta)` → contenedor OpenSSL: `"Salted__" ||
   salt8 || ciphertext`.
3. Derivación EVP_BytesToKey, MD5, 1 iteración, contraseña
   **`"securedjson"`** (constante de formato, `p5.f.f8813a`, no
   credencial de cuenta): `D1 = MD5("" + "securedjson" + salt)`,
   `D2 = MD5(D1 + "securedjson" + salt)`,
   `D3 = MD5(D2 + "securedjson" + salt)`,
   `key = D1||D2` (32 bytes), `iv = D3` (16 bytes). Implementado en
   el APK con `org.apache.commons.ssl.OpenSSL.decrypt("aes256",
   "securedjson", bytes)`.
4. `AES-256-CBC/PKCS#7(key, iv, ciphertext)` → JSON UTF-8.
5. Si OpenSSL no puede descifrar, `p5.f.a` devuelve la cadena tal
   cual (el script admite también JSON sin cifrar que empiece por
   `{`). El JSON en vivo trae caracteres de control crudos dentro de
   valores de texto; `org.json` los tolera, así que el script parsea
   con `strict=False`.
6. `MainActivity$b0.a` lee `Version` y la compara como double con la
   versión guardada: si la remota es mayor, muestra el diálogo de
   actualización con `Message`; si no, "You Using The Latest Config
   Update!".

### Aplicación de la actualización (`m5.a`, `MainActivity$b0$a`)

Al aceptar, la app guarda la **respuesta cifrada tal cual** en SQLite
(`system.db`, tabla `tcodes_table`, `m("1", str)` gratis /
`m("2", str)` VIP), guarda `Version` en preferencias (y `WSDomain`
si el JSON lo trae; el catálogo en vivo no lo trae) y reinicia
`MainActivity`. Cada lectura (`m5.a.b()` gratis, `m5.a.g()` VIP)
descifra con `p5.f.a`.

### Catálogo integrado

En el primer arranque, `MainActivity.onCreate` copia
`assets/defconf` (y `assets/vip_defconf`) a esa misma tabla SQLite
si está vacía. En este build **ambos assets son idénticos**:
Version 23.08, 20 servidores, 889 tweaks.

### Resultado en vivo (2026-11-13)

| Fuente | Version | Servers | Tweaks | Tweaks con Payload |
| --- | --- | --- | --- | --- |
| Remoto (`--url`) | **50.8** | **23** | **1558** | **1445** |
| `assets/defconf` | 23.08 | 20 | 889 | 849 |
| `assets/vip_defconf` | 23.08 | 20 | 889 | 849 |

El catálogo en vivo es más nuevo que el integrado. El cuerpo remoto
(1.036.137 bytes) es **byte a byte idéntico** al catálogo gratis de
EDOZ Tunnel Pro (mismo SHA-256): ambas apps comparten el mismo
catálogo gratis. Los servidores no traen marca free/premium; la
distinción gratis/VIP es por URL y por fila de la base de datos, no
por campo del JSON.

## Archivos

- `EDOZ_Tunnel.py` — decodificador del catálogo, solo stdlib de
  Python 3.10+ (AES-256-CBC en Python puro; un `--url` completo tarda
  ~50 s, casi todo descifrado). CLI: `archivo | --url [URL] |
  --self-test`, con `-o/--output` y `--summary`.
- `EDOZ_Tunnel.png` — icono del launcher (`res/wI.png` del APK,
  699×688) redimensionado a 512×512.
- Sin `EDOZ_Tunnel_archivos.py`: la app **no tiene formato propio de
  archivo importable**. El manifest no declara ningún intent-filter
  `ACTION_VIEW` para archivos ni esquema URI propio (no hay
  `edoz://` ni `edoztunnel://`); tampoco hay código de
  importación/exportación de perfiles (`.sks`, `.ehi`, `.hat`, etc.).
  Los servidores/tweaks personalizados se crean a mano en la UI y se
  guardan en `system.db`. Tampoco hay esquema de texto propio: solo
  los enlaces estándar vmess/vless/ss/trojan que SP-DECODE ya cubre.

## Notas

- Constantes sin uso en este build (`p5.d`): `a="@mts"` +
  `b="crypt"` (`"@mtscrypt"`, la contraseña de formato de 24clan es
  `"mtscrypt"` sin `@`) y `e="decodevpn"`. Ninguna descifra el
  catálogo de esta app; la contraseña real es `"securedjson"`
  (`p5.f`). No se verificó para qué se usan `a/b/e` en este build.
- `p5.d` también lista paquetes de captura de red/torrent
  (HttpCanary, Packet Capture, etc.) — lista de detección, no afecta
  al descifrado.
- La URL VIP (`p5.d.d`) está vacía por defecto; si en una versión
  futura trae URL, el mismo script la descifra (el asset VIP ya
  abre con `"securedjson"`).
