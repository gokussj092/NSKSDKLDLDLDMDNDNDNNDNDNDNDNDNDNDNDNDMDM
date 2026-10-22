# HTTP Internet Infinito 1.3.9

Paquete `com.internetinfinito.http`, build **139**. Catálogo integrado en el
PR #96, rama `feat/austroplus-vpn-13-0-1-decoders`.

Descarga HTTPS autorizada: **74 servidores**, Version **1103**, **789 campos
procesados (586 no vacíos)**. Todo el JSON coincide con el oracle JDK, la CLI
real y el worker aislado. Son recuentos observados, sin limitar registros.
También se validaron completos el servidor y el usuario incluidos en el APK,
ambos Version 1. No se identificó una fuente remota separada de usuarios.

## Uso

Python >=3.10, `pip install -r requirements.txt`. Conservar los archivos propios
`codec.py` y `field_names.json` y los dos archivos homónimos de la carpeta hermana
`HTTP_FenixVPN`, que aportan validación, Base64, rotación Java y renderizado.

```bash
python server_catalog_decoder.py > catalogo.json
python server_catalog_decoder.py --download > catalogo.json
python server_catalog_decoder.py copia_cifrada.txt > copia.json
python server_catalog_decoder.py --stdin < copia_cifrada.txt > copia.json
```

Fuente fija recuperada de `A2.a.C0003a`:
`https://raw.githubusercontent.com/nemygoku/nemy/refs/heads/main/httpinfi`.
No acepta URLs del cliente ni redirecciones. `run(data: bytes) -> str` y los
modos archivo/stdin son offline. La descarga remota devuelve `Servers`; el
lector admite también documentos `Usuarios` aportados, sin inventar una URL.

## Formato

- `p083u2.c`: Base64, encabezado `WakkoDev`, sal de ocho bytes y AES-256-CBC/
  PKCS7. MD5 encadena digest anterior, contraseña UTF-8 y sal hasta 48 bytes:
  clave de 32 bytes e IV de 16. `assets/LICENSE` aporta las constantes de build.
- `p083u2.d` y `g.a`: Base64 URL-safe de IV16+cifrado AES-256-CBC/PKCS7,
  clave UTF-8 rellenada con ceros a 32 bytes; después rotación Java UTF-16
  `26 - INPUT`, con `INPUT=4`. No usa la clave por versión o ChaCha de SocketClay.
- `field_names.json` conserva los nombres reales de recursos: 29 campos de
  servidores, incluidos `BhttpUpload`/`BhttpDownload`, y siete de usuarios.
  Las claves JSON opacas permanecen intactas; el esquema permite interpretarlas.
  Vacíos, booleanos de control, campos desconocidos, orden de listas, duplicados
  de registros, versiones y notas se conservan. Los errores fallan sin éxito parcial.

Proveedor `http-internet-infinito`, control administrativo, worker e icono PNG
original incluidos. Catálogo público mínimo **22**, con **24 fichas**. Icono
`res/drawable-xhdpi-v4/ic_launcher.png` del split xhdpi, 431×426, bytes exactos.
Entrada/salida del lector: 8 MiB; worker/HTTP mantienen sus presupuestos generales.

Ver `TESTING.md`: comprobación breve solicitada, sin suites completas, ejecución
Android, sesiones VPN ni despliegue VPS. No se añade ruta de archivos exportados.
La fuente de anuncios bitbin no se presenta como catálogo de usuarios y el asset
`config/config.json` no se certifica como formato de catálogo consumido por esta
ruta. APK, catálogos reales y perfiles descifrados quedan fuera de Git.
