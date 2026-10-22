# OnSpace VPN 4.2

Paquete `com.onspace.http`, build 25. Catálogos de **servidores y usuarios**,
integrados como proveedor `onspace-vpn` en el mismo PR #96. Python 3.10+ y
PyCryptodome 3.23.0; no se necesita APK ni biblioteca nativa al ejecutar.

```bash
python server_catalog_decoder.py --all > catalogos.json
python server_catalog_decoder.py --download > servidores.json
python server_catalog_decoder.py --users > usuarios.json
python server_catalog_decoder.py copia-cifrada > resultado.json
python server_catalog_decoder.py --stdin < copia-cifrada > resultado.json
```

Sin argumentos descarga ambas fuentes. `run(data: bytes) -> str` es offline:
acepta un catálogo cifrado individual o el sobre dual de `pack_catalogs`.
La salida conjunta contiene `provider`, `complete:true`, `catalogs.servers`
y `catalogs.users`, cada documento con su propia versión. Una fuente ausente,
equivocada o inválida impide comunicar éxito completo. Se conserva todo el JSON,
incluidos tipos, listas, vacíos, duplicados y propiedades desconocidas.

Fuentes fijas recuperadas de las propiedades `NETWORK` / `NETWORK2` de
`res/raw/dnsd_conf`, usadas por `ConfigUpdate` y `usrUdt`:

- Servidores: `https://raw.githubusercontent.com/El-Patron-Oficial2003/Metodos/refs/heads/main/OnSpace%20VPN`
- Usuarios: `https://raw.githubusercontent.com/El-Patron-Oficial2003/User-Pass-New/refs/heads/main/OnSpace%20VPN`

La descarga valida TLS, usa timeout, rechaza redirecciones/HTML y limita bytes.
El broker Cloud selecciona ambas fuentes por ID fijo y mantiene controles de
DNS/IP. No acepta URL arbitraria. El máximo del lector/sobre es 8 MiB; los
presupuestos generales del worker y transporte se mantienen.

Receta confirmada en este APK:

1. `AESCrypt.genString` convierte pares del alfabeto `@#$_&-+()/*"!:;?` a bytes
   que contienen Base64 estándar.
2. AES-256-CBC, IV de 16 ceros y PKCS7. Clave SHA-256 del hexadecimal mayúsculo
   UTF-8 de la constante `netconexionestunnel`, recuperada de `ConfigUtil$1`.
3. Los campos conocidos usan AES-128-CBC/IV cero y Base64, clave de formato
   `speedtunnel@2406` (`SSH_SSL`), seguido por `Vainilla/Choco` con ROT24.
   La rotación respeta los predicados Java sobre unidades UTF-16.

Campos de servidor: `ServerIP`, `ProxyIP`, `ServerUser`, `ServerPass`, `Payload`,
`SNI`, `Slowchave`, `Nameserver`, `Slowdns`, `V2rayConfig`, `UdpServer`, `UdpObfs`,
`UdpAuth`, `UdpDown`, `UdpUp`, `UdpBuffer`. Usuarios: `Username`, `Password`,
`Obfs`, `Auth`, `ID`, `Path`. Puertos, nombres, banderas y opciones se conservan
como fueron almacenados. Los desconocidos no se interpretan como ciphertext.

Se reutiliza el motor HTTP Jireh con parámetros keyword-only, sin cambiar sus
claves/rotación predeterminadas ni modificar estado global. Conservar
`codec.py`, `../HTTP_Jireh/codec.py`, `../HTTP_FenixVPN/codec.py` y
`../HTTP_FenixVPN/field_names.json` si se copia fuera del repositorio.

**Descarga real autorizada del 2026-10-22:** 164 servidores, versión **1662**;
una entrada de usuarios, versión **63**. Ambos JSON y **704 campos cifrados no
vacíos** coinciden íntegramente con JDK independiente, CLI con HTTPS real y
worker aislado. Los recuentos son observaciones, no límites del lector.

El icono WebP original se conserva y su PNG Cloud tiene exactamente los mismos
píxeles RGBA, sin redimensionar. La integración es de catálogos; no se certifica
un formato de archivo exportado sin una muestra. Ver [TESTING.md](TESTING.md).
