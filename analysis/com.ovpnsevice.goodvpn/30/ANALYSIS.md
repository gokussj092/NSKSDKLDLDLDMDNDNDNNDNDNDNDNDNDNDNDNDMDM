# GOOD VPN 3.0 — ANALYSIS

Fecha de verificación: 2026-11-17. Paquete `com.ovpnsevice.goodvpn`,
versionCode 30, versionName 3.0, minSdk 32, targetSdk 36,
desarrollador NAMO DATA NETWORK (antes NONGOHM DEV). APK: XAPK de
APKPure (34.805.320 B, SHA-256
`792e46ae687fb38dc215431295019420ddb78c4ea3b0f3be7780e36d5f70ab0c`,
coincide byte a byte con lo publicado por APKPure). Base 10.263.875 B.
Versión verificada con dos espejos frescos de Play: AppBrain (rastreo
<1 min antes de la lectura, 2026-11-17 15:43 UTC) indica 3.0, última
actualización 9 de noviembre de 2026; APKPure indica 3.0, 10 de
noviembre de 2026. Sin trabajo previo en tandas 1–15 (las menciones
viejas de "goodvpn" son del dominio `pphdevgoodvpn.shop` de PPH VPN,
otra app distinta). No confundir con PPH GOOD VPN (`com.skphvpn.mm`,
`pph-good-vpn` del repo).

Librerías nativas (todas en `config.arm64_v8a.apk`; la base no trae
ninguna): `libapi-good.so` (4.312 B, propia de la app: devuelve la URL
del catálogo y la clave), `libgojni.so`, `libhysteria.so`,
`libv2ray.so`, `libovpncli.so`, `libtun2socks.so`, `libdns.so` /
`libpdnsd.so` (genéricas). No hay `libputils.so` ni ninguna otra
librería propia.

## Método exacto del catálogo

### Descarga

- **Endpoint activo:**
  `https://raw.githubusercontent.com/Anurak2534/ohmvpn/refs/heads/main/newgood.json`
  (GET). Es una URL fija sin parámetros, devuelta por el método nativo
  `MainDetail.a()` (`Java_com_ovpnsevice_goodvpn_MainDetail_a` en
  `libapi-good.so`; la única otra cadena del `.rodata` es la clave).
  La URL completa está en la constante `CATALOG_URL` del script.
- **Dónde vive la URL en el APK:** `MainActivity.z()` crea la petición
  con `ne.H(MainDetail.a())` (OkHttp: `Request.Builder.url(...)`, sin
  cabeceras propias, sin cuerpo) y la encola con `ne.G` / `ko0`; la
  respuesta la recibe `tc.c`, que lee el cuerpo como cadena UTF-8 solo
  si la respuesta es 2xx y lo pasa a `nc0` en el hilo de UI.
- **Petición replicada:** GET plano, `User-Agent: okhttp/5.2.1` (el UA
  por defecto de la pila OkHttp 5.2.1 de la app). El servidor responde
  **200 a cualquier User-Agent** (verificado con el UA por defecto de
  curl y con Mozilla). Sin autenticación, token de sesión, firma ni
  parámetros.

### Descifrado de la respuesta

Handler `nc0` (y `xm0.a()` al leer el archivo local):

1. **`hc1.g(respuesta)`**: Base64 estándar artesanal (mismo alfabeto;
   ignora los saltos de línea que Android Base64.DEFAULT inserta cada
   76 caracteres).
2. **`an2.c(bytes, MainDetail.b().getBytes("UTF-8"))`**: **XXTEA**
   (variante con delta `0x2E0BA747`, distinto del `0x9E3779B9`
   habitual), clave `goodvpn090529` (de `MainDetail.b()`,
   `Java_com_ovpnsevice_goodvpn_MainDetail_b`), rellenada con ceros
   hasta 16 bytes, palabras little-endian de 32 bits y tamaño original
   en la última palabra.
3. Resultado: **JSON UTF-8 completo**, sin filtrar campos.
4. El formato **no tiene MAC**; la validación estructural no equivale a
   autenticación criptográfica.

### Valores internos en Base64

Varios campos del catálogo vienen a su vez en Base64 (con saltos de
línea cada 76 caracteres) y la app los descifra al usarlos con `od.h`
(getters de `ea1`: `SERVER_HOST`, `USERNAME_SERVER`,
`PASSWORD_SERVER`, `OPENVPN_CINFIG`, `PAYLOAD`, `PROXY_HOST`,
`DNSTT_DNS`, `DNSTT_PUBLICKEY`; `MainActivity.G` hace lo mismo con el
campo V2Ray del servidor). El script descifra exactamente esos campos
(`B64_FIELDS`): en Servers `ServerIP`, `Username`, `Password`,
`setOpenVPN`, `V2Ray`, `ServerDNS`, `Cloudfront`, `NameServer`,
`PublicKey`, `UDPConfig`; en Networks `Payload`, `SquidProxy`, `Sni`;
y `setOpenVPN` a nivel superior. Un campo que no descifre se deja como
está y se reporta en `undecoded_fields` (en vivo: ninguno).

### Flujo en la app

- Al arrancar / al pulsar actualizar, `MainActivity.z()` descarga el
  documento; `nc0` lo descifra, parsea el JSON y compara `"Version"`
  (como double) con la versión guardada: si es mayor, muestra el
  `"Message"` (aviso de actualización) y, al aceptar, guarda el JSON
  re-cifrado con `od.g` = `an2.d` (XXTEA cifrar) + Base64 en
  `filesDir/profile.json` (`ys` caso 2).
- `xm0.a()` lee `profile.json` (o devuelve null si no existe) y
  normaliza nombres heredados: `Name` → `ServerName`,
  `Flag` → `ServerFlag`, `SSLPort` → `OpenVPNSSLPort`/`SSHSSLPort`,
  `OvpnCertificate` → `setOpenVPN`, elimina `Info`; en Networks
  `Name` → `PayloadName`, `Info` → `PayloadInfo`,
  `Flag` → `PayloadFlag`, elimina `AutoReplace`, `SSLPort`,
  `NetworkBackQuery`, `NetworkFrontQuery`; si falta `ServerDNS` en un
  servidor, toma el valor de `ServerIP`. El catálogo vivo ya usa los
  nombres nuevos, así que la normalización es un no-op sobre él.
- Las cadenas de la app están ofuscadas con R8 (`jw1.x(long)` sobre
  una tabla de 2 cadenas, 8.191 + 6.103 caracteres). La re-implementación
  en `work/jw1.py` está verificada contra 8 constantes conocidas
  (`api-good`, `Servers`, `Networks`, `Version`, `Message`,
  `profile.json`, `update`): ojo, el jadx de `i2.m` descompila mal los
  desplazamientos finales (los hace sobre int, cuando el bytecode hace
  desplazamientos sobre long) — la versión de `work/jw1.py` sigue el
  bytecode DEX, no el jadx.

## Resultado en vivo (2026-11-17, re-corrido el mismo día)

| Fuente | Versión | Servidores | Payloads (Networks) | JSON (bytes) | Cifrado (bytes) |
|---|---|---|---|---|---|
| GET oficial (`--url --summary`) | **21.8** | **13** | **14** | 39.761 | 69.064 |

- Secciones del documento: `Version`, `Message`, `Servers`,
  `Networks`, `setOpenVPN` (vacío a nivel superior).
- `Message` es el aviso de actualización fechado 16/11/26.
- Servidores (13, todos con bandera `th`): `SelectType` Default 12 /
  UDP 1; 12 tienen usuario/contraseña/`setOpenVPN` y 1 no (el UDP,
  que usa `UDPConfig`).
- Networks/payloads (14, todos `Protocal` OVPN): `SelectedProtocal`
  HTTP Proxy 7, HTTP Proxy(Cloudfront) 4, UDP Hysteria 1, SSL SNI 1,
  SlowDNS 1; 11 tienen `Payload`/`SquidProxy` y 3 no (los no-HTTP).
- `undecoded_fields`: `[]` — todos los valores internos descifraron.
- Re-corrida en vivo byte por byte idéntica al `live.json` entregado
  (ver RESULTS.md).

## Archivo profile.json — el único archivo de la app

- **La app NO importa archivos de configuración del usuario.**
  El manifiesto no tiene ningún intent-filter VIEW para archivos, no
  hay ninguna actividad que maneje `ACTION_GET_CONTENT` /
  `ACTION_OPEN_DOCUMENT`, y no hay selector de archivos en
  `MainActivity`, `MainSettings` ni `MainHotspot`. No existe ningún
  formato `.ovpn`, `.json` ni similar de importación, y no se construyó
  ningún decodificador `.sks` (la app no lo usa).
- El único archivo que la app lee es su propio catálogo en caché,
  `filesDir/profile.json`, escrito con `od.g` (XXTEA + Base64) y leído
  con `an2.c` — **exactamente el mismo formato cifrado que la
  respuesta remota**. `Good_VPN_archivos.py` descifra ese archivo (y
  cualquier respuesta de catálogo guardada) con el mismo algoritmo, y
  su `--self-test` verifica el round-trip cifrar → descifrar.
- **Pendiente:** no existe ningún `profile.json` real extraído de un
  teléfono con el que probar el extremo a extremo; el formato ya está
  verificado contra la respuesta remota en vivo, que es idéntica.

## Esquemas de texto/enlaces — ninguno propio en vivo

- **Manifiesto:** no hay ningún intent-filter con esquema propio de la
  app. No se construyó `Good_VPN_textos.py`.
- **`vmess://`, `vless://`, `trojan://`, `ss://`:** aparecen como
  literales en el DEX, pero solo dentro de la librería v2rayNG
  empaquetada (`V2RayConfigManager.convertToConfig`), que parsea el
  campo `V2Ray` que trae el propio servidor del catálogo
  (`MainActivity.G` lo descifra con `od.h` antes de convertirlo). No
  hay ninguna UI para pegar/importar enlaces del usuario ni lectura de
  portapapeles con esos prefijos: no es un importador de enlaces de
  usuario.
- No hay esquema `goodvpn://` ni similar.

## Auditoría HMAC (obligatoria, AGENTS.md §2.2)

- **Integridad de archivos/catálogos:** NOT_OBSERVED — el formato no
  tiene MAC ni HMAC; la validación es estructural (JSON válido, listas
  `Servers`/`Networks` presentes, longitud interna XXTEA coherente).
- **Derivación criptográfica:** NOT_OBSERVED — sin HMAC en la
  derivación; la clave es una constante fija de formato
  (`goodvpn090529`) con delta fijo `0x2E0BA747`.
- **Transporte VPN:** NOT_OBSERVED — no se revisó el transporte VPN.
- **Autenticación de conexión:** NOT_OBSERVED — no se observó HMAC de
  autenticación de conexión.

## Integración al repo (ruta y advertencias)

- **Ruta recomendada: supplied-only, como su vecina `pph-good-vpn`.**
  Una sola petición GET de URL fija, sin secretos: el broker supplied
  la descarga y la tarjeta se genera sola desde la entrada supplied
  (`SUPPLIED_CATALOG_ITEMS`). El camino genérico de `decode_one()`
  (`module.decode(...)`) cubre el catálogo sin rama nueva, y el camino
  genérico de `file_decode()` (`module.decode(...)`) cubre
  `Good_VPN_archivos.py` como `fileModule` sin rama nueva.
- **Alternativa C8 (coherente, patrón `hx-tunnel`):** `Good_VPN.py`
  expone `run(bytes) -> str`, así que una entrada C8 es mecánicamente
  posible: broker de URL única + bridge. PERO no se pueden registrar
  ambas a la vez sin decidir: el broker prefiere supplied siempre y el
  bridge prefiere supplied salvo que el id esté en el conjunto de
  exclusión de `catalog_vpn_bridge.decode()`. Si Pedro prefiere C8,
  hay que añadir `"good-vpn"` a ese conjunto (como `hx-tunnel`) y la
  entrada supplied seguiría alimentando la descarga; si prefiere
  supplied-only, no hace falta nada en C8 ni en el broker. Ver spec
  exacta y decisión en el REPORT de entrega.
- **`extensions: []`, `textPrefixes: []`:** sin entradas en
  `file-formats.json`, `text-formats.json` ni `_C8_FILE_ENGINES`.
- **Icono:** `good-vpn.png` 512×512 en
  `cloud/web/public/server-vpn-icons/` y `Good_VPN.png` en el
  directorio del proveedor (mismo SHA-256; copiado sin recodificar del
  XAPK).
- **CATALOG_VERSION:** no se toca en este staging (86 en el head
  `5df9fc50`); +1 una sola vez para toda la entrega cuando se aplique
  el parche.

## Estado

- **catalog:** VERIFIED — descarga en vivo verificada, re-corrida byte
  por byte idéntica.
- **files:** VERIFIED (formato = cuerpo remoto) — falta un
  `profile.json` real de teléfono.
- **text:** NOT_APPLICABLE — sin esquema propio.
- **export:** PENDING — sin compartir por código en 3.0.
