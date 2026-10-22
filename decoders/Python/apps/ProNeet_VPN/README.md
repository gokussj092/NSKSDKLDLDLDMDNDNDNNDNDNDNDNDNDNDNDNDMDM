# ProNeet VPN 27.11

Paquete `com.proneet.vpn`, build 88. Lector offline de los catálogos completos
de modo usuario y modo token, registrado en el worker `proneet-vpn` del PR #96.

**Estado remoto del 2026-10-22:** ambas URLs oficiales devuelven HTTP 200 con
un único byte `0A` (salto de línea). GitHub confirma el mismo contenido vacío.
La ficha se muestra con su icono y **descarga desactivada**. El lector funciona
con ambos catálogos incluidos en el APK; no se presenta eso como una descarga
actual de servidores. Habilitar el broker después de validar respuestas oficiales
no vacías y ambos documentos completos.

Requisitos: Python 3.10+ y PyCryptodome 3.23.0. Conservar `codec.py`,
`../HTTP_FenixVPN/codec.py` y `../HTTP_FenixVPN/field_names.json` al copiar fuera
del repositorio. No requiere APK, Android o bibliotecas nativas para ejecutarse.

```bash
python server_catalog_decoder.py copia-cifrada > catalogo.json
python server_catalog_decoder.py --stdin < copia-cifrada > catalogo.json
python server_catalog_decoder.py --usuario > usuario.json
python server_catalog_decoder.py --token > token.json
python server_catalog_decoder.py --all > catalogos.json
```

Las tres últimas opciones consultan las fuentes fijas y actualmente terminan
con código 1 y stdout vacío por el contenido remoto. Sin argumentos intenta
ambos modos. Los errores van a stderr. `run(data: bytes) -> str` es offline;
acepta una copia cifrada individual o el sobre dual de `pack_catalogs(usuario,token)`.
La salida dual conserva cada versión bajo `catalogs.usuario` / `catalogs.token`,
con `provider` y `complete:true` únicamente si ambos documentos se abren.
Entrada/salida/sobre limitados a 8 MiB, sin límite por número de servidores.

Fuentes recuperadas de `ConfigUpdate`, seleccionadas por `Settings.isUserMode`:

- Usuario: `https://raw.githubusercontent.com/ProNeet-27/ProNet/refs/heads/main/MODO%20USUARIO`
- Token: `https://raw.githubusercontent.com/ProNeet-27/ProNet/refs/heads/main/MODO%20TOKEN`

El CLI valida TLS, usa timeout y rechaza redirecciones, HTML y respuestas
vacías/excesivas. No admite una URL arbitraria por argumentos.

`AESCrypt.convertCustomToBase64` transforma los índices 0–64 de
`!?-=∆×÷ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/` a
Base64 estándar, incluido el padding personalizado en el índice 64. Los símbolos
restantes de la constante Java no son válidos. Después aplica AES-256-CBC,
IV cero, PKCS5/PKCS7 y clave SHA-256 de `Proneet` en UTF-8. Los campos de
`LoadConfig` usan la misma receta con SHA-256 de `Key: =Kenova_code`.

Los 23 campos confirmados son `ServerUser`, `ServerPass`, `ServerIP`,
`ServerPort`, `ProxyIP`, `ProxyPort`, `SSLPort`, `Payload`, `SNI`, `Slowchave`,
`Nameserver`, `Slowdns`, `udpserver`, `udpauth`, `udpobfs`, `udpbuffer`,
`udpdown`, `udpup`, `v2rayJson`, `serverktun`, `portktun`, `userktun`, `passktun`.
Se conservan nombres, banderas, tipos, vacíos, duplicados y campos desconocidos.
Los campos internos con JSON mantienen su tipo string. No se aplican filtros
de selección de la app ni se omiten registros de otros protocolos.

El modo token sustituye credenciales por valores de dispositivo al conectarse
en Android. Este lector devuelve los valores almacenados en el catálogo; no
genera una identidad de dispositivo ni realiza una conexión VPN.

Catálogos reales incluidos: **25 servidores usuario / 23 token**, ambos versión
**1.0.0**. Los dos documentos completos y **572 campos cifrados no vacíos**
coinciden con JDK independiente, CLI offline y worker aislado. Son recuentos por
modo, no una afirmación de 48 servidores distintos. Ver [TESTING.md](TESTING.md).
No se registra una extensión de perfil exportado sin muestra certificada.
