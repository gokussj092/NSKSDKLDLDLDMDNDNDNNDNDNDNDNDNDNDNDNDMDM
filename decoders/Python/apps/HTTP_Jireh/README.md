# HTTP Jireh 2.0

APK analizado: `com.jirehvpn`, versión **2.0**, versionCode **11**.
Carpeta independiente dentro de `decoders/Python/apps/`; rama
`feat/austroplus-vpn-13-0-1-decoders`, PR #96. No requiere el APK para ejecutar los lectores.

## Uso

Python 3.10 o posterior y `pip install -r requirements.txt`.
Desde esta carpeta:

```bash
python server_catalog_decoder.py > servidores.json
python server_catalog_decoder.py --users > usuarios.json
python server_catalog_decoder.py copia_cifrada.txt > catalogo.json
python server_catalog_decoder.py --stdin < copia_cifrada.txt
python file_decoder.py perfil.sks > perfil.json
python file_decoder.py < perfil.sks > perfil.json
```

Sin argumentos el lector de catálogo descarga la URL original de **servidores**,
la descifra e imprime todo el JSON. `--users` descarga el catálogo de usuarios
separado. Archivo y stdin funcionan sin red; no aceptan URLs arbitrarias.
El ZIP conserva las carpetas hermanas `HTTP_Jireh/` y el soporte mínimo
`HTTP_FenixVPN/` requerido por el importador compartido: extraer ambas juntas.
Dentro del repositorio no hace falta copiar nada.

## Catálogos y métodos confirmados

- Servidores: `https://raw.githubusercontent.com/alvarofelizzola/GEN-JIREH/refs/heads/main/GENERADOR`.
- Usuarios: `https://raw.githubusercontent.com/alvarofelizzola/USER-JIREH/refs/heads/main/USUARIO`.
- Ambas direcciones proceden de `res/raw/dnsd_conf`, propiedades `NETWORK` y
  `NETWORK2`, seleccionadas por `AsyncTaskC3937` y `AsyncTaskC3912`.
- Copias incluidas: `assets/config/config.json` y `assets/flags/st.png`.
  La segunda es texto cifrado, aunque su nombre termine en PNG. Las copias
  privadas actualizadas se llaman `Config.json` y `st.png`.
- Sobre: cada par de símbolos del alfabeto `@#$_&-+()/*"!:;?` representa un byte
  del texto Base64. Base64 produce el ciphertext AES-256-CBC/PKCS7, IV de 16
  ceros. La clave es SHA-256 del **hexadecimal mayúsculo de los bytes UTF-8** de
  la constante `Conexcol@45208!`. No se usa MD5 ni PBKDF2 para este catálogo.
- Segunda capa: los 16 campos de servidor y seis de usuario enumerados en
  `codec.py` usan Base64 estándar → AES-128-CBC/PKCS7, IV cero y constante
  `conexcolvpn@2308` → rotación Java de letras con desplazamiento **22**.
  Se reproducen `Character.isLetter` y `Character.isUpperCase` sobre UTF-16;
  no se aplica una sustitución ASCII a todo el documento.
- `Name`, puertos, país, banderas, `OtrasConfig`, booleanos y claves desconocidas
  conservan su valor y tipo. No se renombran campos ni se combinan catálogos;
  el campo vacío opcional permanece vacío. No se intentan descifrar valores
  desconocidos solo porque se parezcan a Base64.

Trazas: `p125o00O0oO/AbstractC3936` y `C3940` (sobre y constante),
`p124o00O0o0o/AbstractC3935` (campos), `C3911` (usuarios), y
`com/jireh/http/JirehActivity.o000o0OO`, `o000Oo0o`, `o00Oo0`, `o00O0O`
(consumidores, clave de recurso y rotación `26 - 4`).

## Archivos .sks

`ConfigImportFileActivity` acepta `.sks` y llama a
`p129o00O0oo0/AbstractC3975.OooO00o` → `OooO0O0` → `Properties.loadFromXML`.
Se confirmaron directamente dos variantes en este APK:

1. `Base64(salt32).Base64(nonce12).Base64(ciphertext+tag16)`,
   PBKDF2-HMAC-SHA256, 1000 iteraciones, clave de 128 bits y constante
   `fubvx788b46v`, AES-GCM sin AAD.
2. Variante antigua: bytes DES-ECB/PKCS5; `DESKeySpec` toma los primeros ocho
   bytes de `cinbdf665$4`, es decir `cinbdf66`.

Fuentes: `o00OO0/C4056`, `C4054`, `o00OO0O0/C4112`, `EnumC4110`, `EnumC4111`
y `o00OO00O/AbstractC4084`. Estos parámetros coinciden byte a byte con el
importador de HTTP FenixVPN; se reutiliza ese motor y su validación sin crear
otra ruta `.sks`. La ruta histórica SocksIP JSON `d`/`v` sigue independiente.
La salida contiene todas las entradas ordenadas, claves duplicadas, vacíos,
texto multilínea y `raw_xml` exacto; no transforma indicadores en booleanos.

Existe actividad de exportación, pero su `onClick` observado solo retorna.
**No se certifica exportación operativa en esta versión.** No se adjuntaron
exportaciones reales independientes: se validó el importador con vectores
sintéticos Java GCM y DES. No se identificó un esquema propio de enlaces de
perfiles en las rutas analizadas; no se inventa un tercer lector de enlaces.

## Resultado e integración

Verificado el 2026-10-19: copia incluida con **1 servidor** y **1 usuario**;
catálogos remotos con **109 servidores** y **1 usuario**. Paridad JSON completa
Java/Python, incluyendo **1744 campos cifrados de servidores remotos** y seis
de usuarios. El número remoto puede cambiar cuando el proveedor actualice.

Cloud usa el ID fijo `http-jireh`, descarga solo el catálogo de servidores y
llama a `run(data: bytes) -> str` sin red dentro del worker. Catálogo público
mínimo **10**. Icono original exacto tanto aquí como en
`cloud/web/public/server-vpn-icons/http-jireh.png`: 512×512, 141600 bytes,
SHA-256 `91d4b152a6087a0b60656de9d03444c60199ab4928d8af0c517ab5be0270088e`.

Límites: 5 MiB para archivos, 8 MiB para catálogos/salida, profundidad 64;
GCM autenticado, padding validado, entidades XML y JSON ambiguo rechazados.
Descarga HTTPS fija con plazo de 25 segundos, máximo 8 MiB, HTTP 200,
contenido sin compresión y sin redirecciones. Los errores no imprimen valores
de entrada. Los resultados completos pueden incluir credenciales: conservarlos
localmente. El repositorio y ZIP no contienen APKs, catálogos reales ni sus
resultados. Ver `TESTING.md` y `manifest.json`.
