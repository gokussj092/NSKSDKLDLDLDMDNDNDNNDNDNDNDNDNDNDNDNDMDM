# HTTP Wakko 4.9

Paquete `com.wakko.http`, versionCode **40**. Lector Python del catálogo para
SP-DECODE Cloud, sin APK ni bibliotecas nativas al ejecutar. Rama
`feat/austroplus-vpn-13-0-1-decoders`, PR #96.

## Alcance confirmado

- Descarga real autorizada de **91 servidores, Version `116`**, y **2 entradas
  de usuarios, Version `8`**. Son observaciones, no límites del número de perfiles.
- Ambos JSON completos coinciden con el oracle independiente Java: **725 campos
  cifrados no vacíos de servidores y 10 de usuarios**, incluidos los cuatro
  valores BHTTP de los dos servidores tipo 5. Se preservan todos los registros,
  claves opacas, vacíos, tipos, anuncios y secciones desconocidas.
- Proveedor `http-wakko` registrado, con control administrativo y mínimo del
  catálogo público **16**. Cloud descarga ambas fuentes en paralelo y el worker
  aislado las abre con sus versiones independientes.
- Las copias del APK también coinciden completas: 1 servidor y 2 entradas de
  usuarios, ambas Version `1`, con 17 campos cifrados no vacíos.
- No se identificó un formato de perfil exportado ni una ruta de importación/
  exportación en esta compilación. No se registra una extensión o esquema nuevo.

## Uso

Python >=3.10 y `pip install -r requirements.txt`. Si se copia fuera del
repositorio, conservar las carpetas hermanas `HTTP_Wakko`, `HTTP_SocketClay`
(codec y mapa de campos) y `HTTP_FenixVPN` (codec y mapa de campos). Las primitivas
compartidas están verificadas por separado para este APK; el esquema Wakko es propio.

```bash
python server_catalog_decoder.py > catalogos_completos.json
python server_catalog_decoder.py --all > catalogos_completos.json
python server_catalog_decoder.py --download > servidores.json
python server_catalog_decoder.py --users > usuarios.json
python server_catalog_decoder.py copia_cifrada.txt > copia.json
python server_catalog_decoder.py --stdin < copia_cifrada.txt > copia.json
```

Sin argumentos o con `--all`, descarga ambos catálogos completos. `--download`
selecciona servidores y `--users` usuarios. Archivo/stdin y `run(data: bytes) -> str`
son rutas sin red. No se aceptan URLs proporcionadas por el cliente.

Cloud transporta los bytes originales mediante `spdecode-wakko-catalogs-v1`:

| Salida | Contenido |
| --- | --- |
| `provider` | `http-wakko` |
| `complete` | `true` solo si ambas fuentes son válidas |
| `catalogs.servers` | Documento íntegro con su propia `Version`, `ReleaseNotes`, `Servers` y campos adicionales |
| `catalogs.users` | Documento íntegro con su propia `Version`, `Usuarios` y campos adicionales |

Una descarga o descifrado fallido rechaza toda la operación. No se recortan
listas ni se devuelve éxito con una fuente ausente. Cada descarga admite 8 MiB;
el paquete combinado admite 8 MiB, y Cloud conserva su presupuesto de salida
4 MiB y respuesta HTTP 6 MiB. Si se exceden, hay error explícito. Estos límites
no excluyen registros de los documentos observados.

Fuentes directas fijas verificadas, únicamente en backend:

- Servidores: `https://dl.dropboxusercontent.com/scl/fi/a6grfye2vx80gxxydc6aw/ServersWK2?rlkey=ulmj9oxy1xx3fedhrtnzdwrxm&st=93x7687n&dl=1`
- Usuarios: `https://dl.dropboxusercontent.com/scl/fi/2sc3ud954k0ai07trkdhj/UsersWK?rlkey=k4wqqaawxcddx0kc1sfanof9r&st=dwrzwrmv&dl=1`

Las dos rutas provienen de `SkProtect` (`o00o00.C7033`, C7051/C7052), llamadas
por `WakkoMainActivity` para actualizar archivos distintos. Los enlaces
`www.dropbox.com` del APK redirigen al CDN firmado; los documentos descargados
son byte a byte idénticos a estas fuentes directas, que no requieren redirección.

## Método recuperado de build 40

1. `o00OoOOO.C6851` carga `assets/flags/us.png`, busca `WKCFGSTART` y abre el
   bloque posterior con `ooOoO.o0oo0o00`: ChaCha20-Poly1305 IETF, nonce12 y tag16,
   sin AAD. JNI `libconscrypt.so:0x3d2e8`, clave fija en `0x13d2c`.
   El tag valida los parámetros de compilación `NIGHT_MODE`, `UDP_AUTH`, `INPUT`.
2. Las copias actuales `flags/config.png` y `flags/usr.png` y las respuestas
   remotas son Base64 de `WakkoDev || salt8 || AES-256-CBC/PKCS7`.
   `AbstractC6867` deriva 48 bytes encadenando MD5 del bloque previo, contraseña
   UTF-8 y salt. No se utiliza PBKDF2 para este sobre.
3. El constructor llama `ooOoO.oOoOoOO.oOoOoOoOoo` con la `Version` de cada
   documento. En este `libcrypto.so`, la función está en **0x6e1fc**. Recupera
   la constante mediante el callback ChaCha y calcula SHA-256 de
   `constante || Version`; los primeros 16 bytes se mapean módulo 62 a
   `A-Z a-z 0-9`. `AbstractC6868` completa esos 16 caracteres ASCII a 32 bytes
   con ceros. Se ejecutó el KDF/SHA ARM64 de Wakko para cuatro versiones.
4. Cada campo registrado usa URL-Base64 → ChaCha autenticado → URL-Base64 →
   IV16/AES-256-CBC/PKCS7 → rotación de letras Java `26 - INPUT`, con `INPUT=7`.
   Se conserva la semántica UTF-16 de Java. Se cubre también la forma AES directa
   con vectores sintéticos independientes. Un tag fallido nunca reintenta CBC.
5. `C6863`, `AbstractC6861`, recursos Android y consumidores de nombres/usuarios
   identifican **29 campos de servidor y siete de usuarios**, incluido `Name`
   cifrado. Wakko añade **BhttpUpSlot** y **BhttpDownSlot** a los 27 campos del
   motor SocketClay. Ambos se descifran para `serverType=5`, conservando incluso
   cadenas vacías: los valores predeterminados 16/32 de la UI no se insertan.

La receta y constantes verificadas coinciden con SocketClay, por lo que se
reutilizan sus primitivas y el recorrido validado mediante un esquema por app.
No se deduce esa compatibilidad únicamente por similitud de nombres o UI.
El helper de preferencias seguras no demuestra un importador `.sks` en Wakko.
No se modifica la selección histórica de archivos de otras aplicaciones.

## Icono, disponibilidad y límites

Se conserva el WebP exacto del lanzador predeterminado, recurso `0x7f100014`,
`base.apk:res/mipmap-xxxhdpi-v4/ic_launcher_wkk.webp`, 192×192. El PNG del backend
es una conversión sin pérdida, con píxeles RGBA idénticos y sin redimensionar.
Procedencia y ambos hashes en `manifest.json`.

El broker comprueba DNS/IP públicos y TLS, usa rutas/consultas fijas y rechaza
redirecciones. La versión persistente sube con el catálogo 16, aun cuando los
controles administrativos ya la hubieran elevado por encima del mínimo.
Se mantienen los proveedores desactivados guardados en `switches.json`.

Las descargas externas reales y la CLI se comprobaron por Python/HTTPS. En este
entorno el DNS nativo Node devuelve `EAI_AGAIN`: sus comprobaciones DNS/IP/TLS
son controladas. El flujo autenticado hasta el worker HTTP privado real usa
copias de ambas respuestas autorizadas y devuelve los documentos completos
iguales al oracle. No se afirma una prueba externa desde la VPS.

El sobre CBC exterior carece de autenticación propia. Se validan los tags de
campos, padding, cabecera, JSON sin claves duplicadas/no finito, profundidad y
presupuestos. No se ejecuta el contenido de los resultados ni se imprimen
entradas privadas en errores. No se publican APK, SO, catálogos reales o valores
descifrados en Git/CI.

Integración en código lista en el PR #96; requiere actualizar la VPS para
aparecer en el servicio público. No se fusiona, despliega o publica APK ni
novedades C11 automáticamente. Ver `TESTING.md` y `manifest.json`.
