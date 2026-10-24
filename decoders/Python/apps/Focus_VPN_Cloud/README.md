# Focus VPN Cloud 5.0

Paquete `com.cloud.focus`, build **59**. Lector de catálogo integrado en el
PR #96, rama `feat/austroplus-vpn-13-0-1-decoders`.

Descarga real autorizada: **142 servidores**, Version **1081**, con **590
campos cifrados no vacíos**. El documento completo coincide con el oracle JDK,
la CLI real y el worker aislado. Son recuentos observados, no límites de registros.

## Uso

Python >=3.10 y `pip install -r requirements.txt`. Conservar `codec.py` y la
carpeta hermana `HTTP_FenixVPN`, con `codec.py` y `field_names.json`, para
validación y renderizado compartidos.

```bash
python server_catalog_decoder.py > catalogo.json
python server_catalog_decoder.py --download > catalogo.json
python server_catalog_decoder.py copia_cifrada.txt > copia.json
python server_catalog_decoder.py --stdin < copia_cifrada.txt > copia.json
```

Sin argumentos descarga la fuente fija recuperada de `ConfigUtil`:
`https://raw.githubusercontent.com/Rotdtd/Upagost17/refs/heads/main/NewSepFocass`.
Archivo/stdin y `run(data: bytes) -> str` no usan red. No se aceptan URLs del
cliente ni redirecciones. Se conserva el JSON completo, versiones, notas,
registros, vacíos, tipos y claves desconocidas, sin filtrar ni deduplicar.
Entrada/salida del lector: 8 MiB; Cloud mantiene sus presupuestos generales
de salida y HTTP. Exceso o registro inválido produce error, sin éxito parcial.

## Formato comprobado

- `ConfigUpdate` descarga con GET. `AESCrypt.genString` convierte pares del
  alfabeto de 16 bloques Unicode a bytes, que contienen Base64 del cifrado.
  El lector acepta saltos de línea del documento remoto como hace el downloader.
- La clave exterior es SHA-256 del hexadecimal ASCII mayúsculo de la contraseña
  recuperada; AES-256-CBC, IV cero, PKCS7. No es el motor WakkoDev de otras apps.
- `FocusActivity.o0000Oo` abre 12 campos mediante `SSLdirecto`/RC4. Esa clase
  cachea la primera clave: el consumidor pasa inicialmente
  `String.valueOf(V2Config.secretKeyj)`, cuyo valor inicial es `null`. Copia los
  bytes UTF-8 a 16 bytes y completa con ceros. El oracle JDK reproduce este
  estado inicial y todos los campos reales coinciden. No se ejecutó Android.
- `ProxyIP`, puertos, nombre y banderas se conservan tal como llegan. No se
  intenta descifrarlos por parecer texto Base64. `UseTcp` conserva su texto.
- El catálogo inicial activo es `assets/flags/fc.png`: 1 servidor, Version 1.
  No se certifican las copias distintas de `assets/config/config.*` con esta
  receta. `LINKUPDATEANUNCIOS` alimenta Banner/Intersticial/OpenApp/Recompensado;
  corresponde a anuncios, no a un catálogo de usuarios, y no se integra como tal.

Proveedor `focus-vpn-cloud`, control administrativo y ficha remota registrados.
Catálogo público mínimo **20**, con 22 fichas; switches guardados conservados.
Icono PNG exacto del lanzador, `res/mipmap-xxxhdpi-v4/ic_launcher.png`, 192×192.
No se añade una extensión de archivo ni se modifica Android en esta entrega.

Se hicieron comprobaciones dirigidas, sin suites completas, según petición del
usuario. HTTPS externo y CLI real comprobados por Python; DNS/IP/TLS del broker
Node mediante transporte controlado. No se afirma prueba externa desde la VPS,
despliegue o funcionamiento de sesiones VPN. No se incluyen catálogos reales,
APK o perfiles descodificados en Git. Ver `TESTING.md` y `manifest.json`.
