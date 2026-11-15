# AR PRO VPN — catálogo y archivos .ar

App: AR PRO VPN, paquete `noob.arpro.vpn`, versionCode 1, versionName 1.0.
Fork de v2rayNG ("NoobDev Build"). Sin proveedor en el repo SP-DECODE
(rama feat/nuevas-integraciones); el más cercano, V2ray_Tunnel_Plus,
es otra app.

## Método — catálogo

- Descarga: `GET https://jezvpn.xyz/api/app?json=0b791e09b974f136ed62`
  (URL fija; la app la lee de la preferencia `DefUpdateUrL`, cuyo
  valor por defecto es este endpoint).
- Petición exacta de la app: `HttpURLConnection`, método GET, sin
  cabeceras propias, sin autenticación, sin User-Agent propio.
- Descifrado: cuerpo = una línea Base64 → Base64 estándar → XXTEA
  modificado (delta `0x9A7393B4`, clave `HexXVPNPass` completada con
  ceros a 16 bytes; la última palabra es la longitud del texto) →
  JSON UTF-8.
- Campos: cada valor de texto que es un cifrado Base64 válido se
  descifra con Jdecrypt (AES/CBC/PKCS5Padding, clave = SHA-256 de la
  cadena nativa de libwg-pro.so, IV fijo `01 23 45 67 89 ab cd ef 10
  32 54 76 98 ba dc fe`); los campos en texto plano quedan como están.
  Los payloads de los tweaks también se descifran con Jdecrypt.

## Método — archivos .ar

- Formato: contenido = Base64(AES/CBC/PKCS7Padding(JSON del perfil,
  clave = SHA-256(clave maestra), IV = 16 bytes cero)).
- La clave maestra se deriva en el script como la app
  (AbstractC0858Qk.i()): descifrar el cifrado Base64 fijo con clave
  SHA-256 de la constante fija y IV cero.
- El perfil JSON tiene 28 campos (PSInstall, DeviceID, RootBlock,
  MobileData, ExpireDate, isMsg, CFGMessage, isPassON, MyPass,
  Payload, WSPayload, SNIHost, BUGHost, DNSHost, ProxySet, UDPhost,
  UDPobfs, UDPauth, V2Ejson, v2Esni, isUri, isEreverse, EwgConf,
  TunnelType, isWSProxy, isWS, Server, NoobDev). Las protecciones
  (contraseña, bloqueo de root, DeviceID, expiración, instalador de
  Play Store) se revisan DESPUÉS del descifrado, no son entradas de
  la clave. No hay soporte .sks (excluido).

## Textos/enlaces

Sin esquema funcional propio. La app maneja los enlaces estándar
vmess://, vless://, ss:// y trojan://, ya cubiertos por el núcleo de
SP-DECODE. `AR://` no es un enlace de importación: es un prefijo
aleatorio que la app genera al exportar (20 caracteres al azar).

## Uso

```sh
python AR_PRO_VPN.py --url
python AR_PRO_VPN.py --url -o catalogo.json
python AR_PRO_VPN.py respuesta_guardada.bin
python AR_PRO_VPN_archivos.py perfil.ar
python AR_PRO_VPN_archivos.py --self-test
```

Solo biblioteca estándar (Python 3.10+). El AES es una implementación
pura en Python incluida en cada script.

## Probado en vivo (2026-11-13)

Catálogo remoto: versión 19.2.8, versioncode 1, 9 servidores (todos
categoría Free, todos protocolo vless), 434 tweaks. 977 campos de
texto descifrados con Jdecrypt en el catálogo (servidores, tweaks y
campos de nivel superior). La salida de `--url` es idéntica a
descifrar el cuerpo guardado.

El endpoint ignora Range (responde 200 con el cuerpo completo), así
que no hay reanudación por rangos: ante un cuerpo truncado el script
reintenta el GET simple (la longitud interna XXTEA y el parseo JSON
validan que el cuerpo esté completo).

## Pendiente

- Confirmación de extremo a extremo del decodificador .ar con un
  archivo .ar real exportado por la app: el método está verificado
  contra el código de la app (P() y R() son inversos exactos y el
  round-trip sintético pasa), pero no existe ningún .ar de muestra en
  los assets del APK.
- Las cadenas de la app están ofuscadas con LSParanoid; el endpoint
  y el método se resolvieron con la herramienta de referencia
  paranoid-deobfuscator (1,713/1,713 llamadas en la app de referencia
  y 2,400 cadenas en esta app), no con el puerto en Python.
