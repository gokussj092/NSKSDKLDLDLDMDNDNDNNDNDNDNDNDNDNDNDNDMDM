# NetMx VPN (`com.imxfree.vpn`, 2.0.7 / build 207)

Sin cobertura previa en SP-DECODE (86 carpetas revisadas en
`decoders/Python/apps/`; lo mas cercano, Mx_Tunnel_PRO y TurboMX_VPN,
son otras apps).

## Catalogo

`NetMx_VPN.py`. La app descarga el catalogo con un GET simple, sin
cabeceras propias ni auth (HttpURLConnection, `ConfigUpdate`), y lo
descifra con `AESCrypt` (`ConfigUtil.getJSONConfig`):

```
GET https://raw.githubusercontent.com/MarVarGueZ/Mio/refs/heads/main/vpsvip.json
```

Formato del cuerpo (una linea larga de caracteres de bloque):

```
texto -> genString: cada PAR de caracteres del alfabeto
        "▙▚▛▜▝▞▟▃▄▅▆▇█▉▊▐" es un byte de una cadena Base64
        (primer caracter = nibble alto)
     -> Base64 -> AES-256-CBC/PKCS7
     -> clave = SHA-256(hex en mayusculas de "NetMxVpn2025"),
        IV = 16 bytes cero
     -> JSON: {"version", "releaseNotes", "servers": [...]}
```

La clave es la constante que devuelve `Utils.getDisplayDensity()`
(`"NetMxVpn2025"`); la URL es la constante de
`Utils.getSystemSyncStatus()`. AES-256-CBC implementado en el script en
stdlib puro (verificado contra PyCryptodome con el asset real y con el
catalogo en vivo).

Cada servidor trae: serverName, serverInfo ("México" / "Estados
Unidos"), serverFlag (codigo de 2 letras, `assets/flags/<codigo>.png`),
serverHost, serverPort (443), sni, tunnelType (2 = SSH), serverType
(0 = SSH, 2 = UDP), username/password/payload/proxyHost/proxyPort
(vacios en el catalogo en vivo) y, en los UDP, udpHost/udpPort/udpObf/
udpAuth/udpDown/udpUp. No hay seccion de payloads/tweaks en este
catalogo ni marca de free/premium: todos los servidores listados son
gratuitos.

Prueba real en vivo (2026-11-13): HTTP 200, 179.857 bytes, version
**157, 88 servidores** (86 SSH en el puerto 443 + 2 "UDP
Internacional"), 44 Mexico / 44 Estados Unidos, 0 payloads. El asset
incluido en el APK abre con la misma clave: version 100, 1 servidor
de ejemplo ("Actualiza los servidores...").

Los endpoints `http://mx.teammx.xyz:6888/checkUser` y
`http://us.teammx.xyz:6888/checkUser` que aparecen en el DEX son una
comprobacion de usuario/premium aparte (`DialogHelper.CheckUser`), no
forman parte de la descarga del catalogo y no se usan aqui.

## Archivos

`NetMx_VPN_archivos.py`. La app no tiene formato de perfil propio
(.hc, .hxt, etc.): su unica importacion es el "offline import" de
`ServersActivity`, que lee cualquier archivo como texto y lo guarda tal
cual en `filesDir/Config.json`; `ConfigUtil` lo vuelve a leer con el
mismo `AESCrypt.decrypt`. Es decir, un archivo importable por NetMx ES
un catalogo cifrado con este mismo esquema. El decodificador es el
mismo `decode()` del script de catalogo.

Verificacion: round-trip cifrar/descifrar exacto (incl. Unicode) y
descifrado del asset real del APK (version 100, 1 servidor). No existe
muestra exportada por la app en un telefono (la app no exporta
archivos), asi que la confirmacion extremo a extremo con un
Config.json de telefono queda pendiente; el riesgo es bajo porque el
metodo y la clave estan probados contra el asset real de la propia app.

## Textos

Sin esquema propio: el manifest no tiene intent-filter ACTION_VIEW
para las actividades de la app ni esquema personalizado, asi que no
hay decodificador de enlaces que anadir. Los enlaces estandar
(vmess/vless/ss/trojan) ya los cubre SP-DECODE.

## Uso

```bash
python NetMx_VPN.py --url                 # descarga y descifra el catalogo remoto
python NetMx_VPN.py Config.json           # decodifica un archivo cifrado
python NetMx_VPN_archivos.py Config.json  # idem (decodificador de archivos)
```

Cada script acepta tambien `--stdin` y `-o salida.json`, y
`--self-test` para las pruebas internas sin red. Solo biblioteca
estandar de Python 3.10+.

## Librerias nativas

Todas viven en el split `config.arm64_v8a.apk` (el base no trae
ninguna): libconscrypt_jni.so, libdatastore_shared_counter.so,
libdns.so, libgojni.so (34,6 MB, nucleo xray/v2ray en Go),
libpdnsd.so, libtun2socks.so, libuz.so (24,7 MB, nucleo Go),
libv2ray.so. El catalogo no pasa por el codigo nativo: esta entero en
Java (`imx.free.vpn.util`).

## Pendientes

- Confirmacion extremo a extremo con un Config.json importado en un
  telefono (la app no exporta; habria que importar el catalogo
  remoto guardado como archivo y comprobar que la app lo acepta).
- Ninguna app usa archivos `.sks` ni esquemas de texto propios.
