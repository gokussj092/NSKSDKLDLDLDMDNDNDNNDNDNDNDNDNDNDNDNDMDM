# HTTP SocketClay 3.4.0

Paquete `com.socketclay.http`, versionCode **341**. Lectores Python para el
servidor Cloud de SP-DECODE; no necesitan APK ni bibliotecas nativas al ejecutar.
Trabajo en `feat/austroplus-vpn-13-0-1-decoders`, PR #96.

## Estado confirmado

- **Descarga remota real validada** con autorización explícita del usuario el
  2026-10-21: **86 servidores** (Version `107`) y **2 entradas de usuarios**
  (Version `10`). Son cifras observadas, no límites fijos del lector.
- Los dos documentos remotos completos coinciden con el oracle independiente
  Java: **663 campos cifrados no vacíos de servidores y 10 de usuarios**.
  Se conservan todos los registros, campos vacíos, tipos y metadatos.
- Los enlaces del APK redirigen a un CDN firmado de Dropbox. Sus bytes son
  idénticos a los de las fuentes directas fijas que ahora usa Cloud; no se
  necesita aceptar destinos de redirección dinámicos.
- La CLI descarga ambos catálogos y su resultado completo coincide con el
  trabajador aislado y el oracle. Catálogo público mínimo **15**, proveedor
  `http-socketclay` registrado y sujeto a los controles normales de activación
  del administrador. No se modifica el diseño Android ni el panel.
- `.sks`: importador GCM/DES confirmado por código y vectores Java sintéticos;
  no se proporcionó una exportación real independiente ni se certifica writer.
- La validación anterior de copias del APK sigue vigente: 1 servidor y 2
  entradas de usuarios. No sustituye la comprobación remota actual.

## Uso

Python >=3.10 y `pip install -r requirements.txt`. Dentro del repositorio las
carpetas hermanas ya están presentes. Al copiar este lector aparte, conservar
`HTTP_SocketClay/` y `HTTP_FenixVPN/codec.py` + `field_names.json` juntos.

```bash
python server_catalog_decoder.py > catalogos_completos.json
python server_catalog_decoder.py --all > catalogos_completos.json
python server_catalog_decoder.py --download > servidores.json
python server_catalog_decoder.py --users > usuarios.json
python server_catalog_decoder.py copia_cifrada.txt > copia.json
python server_catalog_decoder.py --stdin < copia_cifrada.txt > copia.json
python file_decoder.py perfil.sks > perfil.json
python file_decoder.py < perfil.sks > perfil.json
```

Sin argumentos, o con `--all`, descarga **ambas fuentes completas**. `--download`
selecciona únicamente servidores y `--users` únicamente usuarios. Archivo/stdin
no acceden a la red. Nunca se aceptan URLs introducidas por el usuario.

Cloud descarga ambos documentos en paralelo y los envía intactos al worker:
`spdecode-socketclay-catalogs-v1` contiene solo dos etiquetas fijas y sus bytes
Base64. La salida es:

| Campo de salida | Contenido |
| --- | --- |
| `provider` | `http-socketclay` |
| `complete` | `true` únicamente cuando se abren ambas fuentes |
| `catalogs.servers` | Documento de servidores completo, con su `Version`, `ReleaseNotes`, `Servers` y claves adicionales |
| `catalogs.users` | Documento de usuarios completo, con su `Version`, `Usuarios` y claves adicionales |

Cada documento mantiene su propia versión; no se mezclan ni sustituyen sus
metadatos. Si una fuente falla, está corrupta o no cabe en el presupuesto de
transporte, se devuelve error explícito. No hay selección de primeros registros,
truncamiento ni éxito con una sola fuente.

`run(data: bytes) -> str` permanece sin red y acepta tanto una copia individual
como el paquete interno con ambos catálogos. No interpreta ni ejecuta enlaces,
comandos, nombres de clases o configuraciones presentes en el resultado.

Fuentes verificadas, únicamente en backend:

- Servidores: `https://dl.dropboxusercontent.com/scl/fi/vh319xyu0ck84ks0wdqw8/ServersSC?rlkey=b9g57byy0igz2jitqix31t4i4&st=evmzpf11&dl=1`
- Usuarios: `https://dl.dropboxusercontent.com/scl/fi/yas4u26xnhdpz4f8qxkp0/UsersSC?rlkey=jtdh2g84uj6y5j9zp4ca929xk&st=hp49nv1g&dl=1`

## Método actual del catálogo

1. `Configs.loadConfig` abre `assets/flags/us.png`, busca `WKCFGSTART` y pasa
   el contenido posterior a `ooOoO.o0oo0o00.o0oooo00`. En `libconscrypt.so`,
   JNI `0x3d2e8`, esto es nonce de 12 bytes, ChaCha20-Poly1305 IETF sin AAD,
   ciphertext y tag de 16 bytes. La clave fija está en `0x13d2c`.
   Así se recuperaron los parámetros de esta compilación, no datos de usuarios.
2. Los catálogos actuales están en `assets/flags/config.png` y `usr.png`.
   Son texto Base64 de `WakkoDev || salt8 || AES-256-CBC/PKCS7`.
   `com.google.webview.AES` deriva clave/IV encadenando MD5 del bloque anterior,
   contraseña `NIGHT_MODE` en UTF-8 y salt, hasta 48 bytes. No usa PBKDF2.
3. `libcrypto.so`, JNI `oOoOoOoOoo` en `0xd9c40`, recupera la constante de
   compilación mediante el callback Java `o0oo00o`. Calcula SHA-256 de
   `constante || Version` y convierte los primeros 16 bytes por módulo 62 al
   alfabeto `A-Z a-z 0-9`. `AESED` completa esos 16 caracteres con ceros hasta
   32 bytes. La receta Java `generateNaju` visible en `Configs` no es la llamada
   que utiliza el constructor; no se tomó como sustituto del método nativo.
4. Los campos registrados en `field_names.json` usan URL-Base64 → ChaCha
   autenticado → URL-Base64 → IV16/AES-256-CBC/PKCS7 → rotación Java de letras
   `26 - INPUT`, donde `INPUT=7`. Se respeta UTF-16 y `Character.isLetter`/
   `isUpperCase`, no una rotación ASCII de todo el JSON. También se cubre
   sintéticamente la forma AES directa de `AESED`, sin el envoltorio nativo.
5. Fuentes de los 27 campos de servidor: `com.google.webview.Servers`,
   consumidores de nombre/información/bandera y sus recursos Android. Los siete
   campos de usuarios incluyen **Name cifrado**, distinto de HTTP FenixVPN.
   Los campos opacos conservan sus nombres, sin inventar alias.

La selección entre campo directo y envuelto se realiza por su longitud antes
de descifrar. Un tag ChaCha fallido nunca dispara un reintento CBC.
Las listas de servidores/usuarios se abren usando su propia `Version`.
Las copias incluidas tienen versión `1`; las remotas observadas tienen
versiones independientes `107` y `10`, ambas comprobadas sin alterar valores.

`SkProtect` contiene también rutas antiguas para `flags/zs.png` y `cy.png`.
No se confunden con los catálogos actuales de `Configs`, ni se anuncia soporte
para esos catálogos heredados. No se identificó un esquema propio de enlaces
de importación que justifique un tercer lector.

## Archivos .sks e integración

`com.socketclay.sshservice.config.ConfigParser` confirma `FILE_EXTENSAO=sks` y
`Cryptor` con `fubvx788b46v`: PBKDF2-HMAC-SHA256, 1000 iteraciones, salt32,
clave de 128 bits, nonce12, tag16, sin AAD. El mecanismo legado usa DES-ECB con
los primeros ocho bytes de `cinbdf665$4`. `convertDataToFile` produce XML Java
Properties; se preservan claves duplicadas, orden, vacíos y `raw_xml` completo.
Estos parámetros coinciden con el motor de HTTP FenixVPN: se reutiliza y la
selección histórica SocksIP JSON `d`/`v` permanece intacta. No se cambia la matriz
C0, no se añade otra extensión `.sks` ni código de descifrado Android.

Límites: archivos 5 MiB, catálogo/salida 8 MiB, profundidad 64. Se validan tags,
padding, forma del JSON, límites y claves duplicadas. El sobre CBC exterior no
tiene autenticación propia; no se afirma una garantía que el formato no ofrece.
Los errores CLI/worker no imprimen valores de entrada ni resultados parciales.

Icono: PNG original exacto, recurso `0x7f080142` de `split_config.xhdpi.apk`,
431×426, 71943 bytes. Hash y procedencia en `manifest.json`.
No se incluyen APK, `.so`, catálogos reales, resultados o credenciales reales en
Git. Las constantes del lector son parámetros fijos de la compilación analizada.

## Disponibilidad y despliegue

El broker usa HTTPS con DNS/IP públicos verificados, TLS validado, origen,
ruta y consulta fijos. Los enlaces directos ya validados no siguen redirecciones.
El proveedor dispone de control administrativo para activar/desactivar el método.
El mínimo del catálogo aumenta a **15**; la huella persistente incluye la revisión
del catálogo, de forma que habilitar una tarjeta ya visible eleva la versión aun
si los cambios anteriores del panel la habían llevado por encima del mínimo.
Se conserva `switches.json` y sus proveedores desactivados.

En este entorno el DNS nativo de Node responde `EAI_AGAIN`. Las descargas reales
se comprobaron por Python/HTTPS; las pruebas de DNS/IP/TLS del broker fueron
controladas. El flujo autenticado completo hasta el worker HTTP real se probó
con copias de esas respuestas autorizadas. No se afirma una conexión externa
Node desde la VPS ni un despliegue que no se haya realizado.

El cambio queda en el PR #96. Requiere actualizar la VPS con esta rama para
estar disponible en el servicio público. No se fusiona ni despliega como parte
de esta validación. No se publican novedades C11 automáticamente.

Ver `TESTING.md`, `manifest.json` y `docs/cloud/CATALOGS_UPDATE_RUNBOOK.md`.
