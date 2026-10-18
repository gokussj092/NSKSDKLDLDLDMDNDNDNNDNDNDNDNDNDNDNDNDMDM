# DTunnel Mod 4.2.5 — catálogo y enlaces vpn://

Lector Python independiente: [`dtunnelmod.py`](../decoders/Python/dtunnelmod.py).
Analizado desde `dtunnelmod.zip`, que contiene `dtunnelmod.apk`:
paquete **`com.dtunnel.v2ray.pro`**, nombre **Fastiver Vpn Pro**,
`versionName=4.2.5`, `versionCode=9`.

## Qué métodos utiliza esta versión

| Método observado | Tratamiento |
| --- | --- |
| Catálogo remoto de servidores | GET HTTPS, Base64 y AES-256-CBC; `--url` o respuesta guardada |
| Enlace `vpn://` | Base64 estándar de un objeto JSON UTF-8; `--link` o archivo de texto |
| Actualizaciones de interfaz y textos | Mismo cifrado, selectores `--kind layout` y `--kind texts` |
| Archivo de configuración para importar/exportar | No se identificó un formato propio ni un flujo de selección/exportación de archivos en las rutas revisadas |
| Caché local de Room | Contenedor interno distinto; no se presenta como exportación de usuario ni se implementa como tal |

No se registra una extensión supuesta `.dtunnel` ni se cambia el motor
histórico DarkTunnel. Un archivo `.txt` aceptado por este script es una
respuesta HTTP o un enlace guardado para análisis offline; no implica que
la aplicación importe ese archivo.

`assets/app_config.json` tiene 30 ajustes de interfaz, **no es un catálogo
local de servidores**. `assets/app_text.json` contiene etiquetas de interfaz.
El catálogo completo procede de la respuesta remota `app_config`. En la
consulta autorizada del 18 de octubre de 2026 se recuperaron sus **46
perfiles reales**, conservando los 22 campos de cada miembro. Esta cantidad
corresponde al identificador de la muestra y a esa respuesta; puede cambiar
y no representa todos los catálogos de otros usuarios del servicio.

## Uso sin APK

Requiere Python 3.10 o posterior y PyCryptodome. El motor no necesita Android,
Java, bibliotecas nativas ni el APK durante su ejecución.

```bash
python -m pip install pycryptodome

# Respuesta cifrada guardada previamente:
python decoders/Python/dtunnelmod.py respuesta_catalogo.txt
python decoders/Python/dtunnelmod.py respuesta_catalogo.txt -o servidores.json

# Enlace, o un archivo de texto que contenga ese enlace:
python decoders/Python/dtunnelmod.py --link 'vpn://BASE64_DEL_JSON'
python decoders/Python/dtunnelmod.py enlace.txt -o perfil.json

# Descarga explícita del catálogo remoto con el identificador original:
python decoders/Python/dtunnelmod.py --url --credentials-file credentials.json -o servidores.json

# Misma descarga, imprimiendo el JSON completo:
python decoders/Python/dtunnelmod.py --url --credentials-file credentials.json

# Otras dos actualizaciones, que no contienen los servidores:
python decoders/Python/dtunnelmod.py --url --credentials-file credentials.json --kind layout -o interfaz.json
python decoders/Python/dtunnelmod.py --url --credentials-file credentials.json --kind texts -o textos.json
```

Para descargar basta el archivo pequeño `credentials.json` del APK, de 110
bytes en la muestra recibida. Si ya se tiene el APK localmente, se puede
extraer una sola vez:

```bash
unzip -p dtunnelmod.apk assets/credentials.json > credentials.json
```

No hace falta subir ni conservar el APK junto al script. El archivo de
identificadores se mantiene fuera del repositorio. Los ejemplos y fixtures
no incluyen sus valores reales. Si se conoce directamente el identificador
que debe llevar la petición, `--request-id-file identificador.txt` lo lee de
UTF-8 y retira solo un LF o CRLF final. No se recibe por argumento de
terminal. Esta opción sustituye a `--credentials-file`.

`--url HTTPS_URL` permite indicar explícitamente otro endpoint. El
identificador se envía a la URL elegida; se exige HTTPS y no se siguen
redirecciones. No hay descargas implícitas desde archivos, enlaces, `run()`
o `decode()`. La descarga no inicia una conexión VPN.

## Petición y selección del identificador

El flujo modificado usa el valor `url` de `assets/config.json` y añade
`/api/dtunnelmod`. En esta muestra resulta:

```text
GET https://dtmod.cloud/api/dtunnelmod
User-Agent: DTunnelMod (@DTunnelMod, @DTunnelModGroup, @LightXVD)
dtunnel-token: <identificador proporcionado por el usuario>
dtunnel-update: app_config
```

| `--kind` | `dtunnel-update` | Estructura observada tras descifrar |
| --- | --- | --- |
| `catalog` (predeterminado) | `app_config` | Array de cadenas, cada una un objeto JSON de perfil |
| `layout` | `app_layout` | Array de cadenas JSON de ajustes de interfaz |
| `texts` | `app_text` | Array de objetos con `label` y `text` |

El botón de actualización normal pasa **`credentials.json.user_id`** a los
tres repositorios. Aunque el encabezado se llama `dtunnel-token`, esto no
significa que se deba usar el campo `token`: ese otro campo participa en un
flujo manual separado. El script usa `user_id` con `--credentials-file` y
no intenta automáticamente el otro valor si se rechaza el primero.

Se observó también el endpoint gRPC del cliente original, pero las rutas de
actualización modificadas llaman a `Light.Crack`; el script reproduce la
petición HTTPS de esa ruta, no el servicio gRPC original.

## Cifrado del catálogo

`Light$1Kirito.d(String)` aplica:

```text
seed = UTF-8("DTunnelModSecret-API-9c69a0b72b442ccac3e6aaaa7630d12f2b351fe395e9fe667efa0907cde90da5")
key = SHA-256(seed)                           # 32 bytes
iv = 00 repetido 16 veces
ciphertext = Base64-estándar(respuesta HTTP)
plaintext = AES-256-CBC-PKCS5Padding(key, iv, ciphertext)
documento = JSON(UTF-8(plaintext))
```

PKCS5Padding de JCE para AES equivale al padding PKCS#7 de bloque 16.
La constante compartida está embebida en el cliente y es material del
formato; no es `user_id` ni `token` de una cuenta. Los controles nativos de
MD5 sobre autor/créditos no intervienen en esta derivación.

El formato **no tiene MAC ni etiqueta de autenticación**. Un padding y JSON
válidos no prueban integridad criptográfica. La aplicación devuelve `[]`
al capturar errores de descifrado; este lector los informa explícitamente.
Solo una lista vacía correctamente descifrada produce `[]`.

Los miembros de texto se interpretan una sola vez como objetos JSON. Se
admiten también objetos directos para inspección compatible, sin adivinar
cifrados interiores. No se descifra recursivamente cualquier campo que
parezca Base64. Se conservan las cadenas de configuración V2Ray, payloads
CRLF, categorías, identificadores, credenciales y campos desconocidos.
No hay límite fijo de cinco, 230, 900 o 1.000 servidores: se procesan todos
los miembros dentro de los límites de recursos descritos abajo.

## Enlaces y almacenamiento interno

`a1.a.d` decodifica el texto posterior a `vpn://` mediante Base64 estándar y
Gson. La capa del enlace no está cifrada. El importador de Android reemplaza
algunos identificadores y crea una categoría local. El script conserva
`id`, `category_id`, `user_id`, `sorter` y cualquier otro campo originales;
no reproduce esos cambios de importación.

Las rutinas internas `com.bumptech.glide.f.o/p` usan un contenedor de caché
con doble Base64, longitud BE32, clave AES aleatoria guardada en el propio
contenedor, IV y AES-CBC con doble padding. Su presencia en Room no demuestra
un formato de intercambio de archivos. Ese lector de base de datos no forma
parte del script.

## API Python y errores

```python
from decoders.Python.dtunnelmod import decode, decode_catalog, decode_link, run

perfiles = decode_catalog(respuesta_bytes)  # list[dict]
perfil = decode_link("vpn://...")          # dict
resultado = decode(contenido_bytes)        # detección local enlace/catálogo
texto_json = run(contenido_bytes)          # str o None; siempre offline
```

La CLI devuelve 0 al completar, 1 por formato/descifrado/descarga y 2 por
errores de archivos o argumentos. Los errores se escriben como JSON en
stderr, sin revelar identificadores ni excepciones HTTP. Un error de
descifrado o de cualquier miembro no produce una lista parcial ni
sobrescribe una salida previa. Errores de escritura del sistema operativo
siguen siendo posibles.

Límites: entrada y respuesta de 32 MiB; JSON de profundidad 64 y hasta un
millón de nodos, contando claves. Se rechazan claves duplicadas, números
no finitos y Unicode inválido. La descarga tiene timeout de 20 segundos
por operación de socket, sin reintentos automáticos ni redirecciones.

## Evidencia y validación

- SHA-256 ZIP: `e099e3d76023e2862e6c29092992da766199c04549d10cbc669a20f7f2c3e1bb`.
- SHA-256 APK: `6d0afdc3ad02873cb146b4995bab9c8ba1f25dbfd86f711ad59d2cff0eba64c4`.
- DEX: `f3.o`, `c3.k` y `d3.l` llaman a `Light.Crack` con selectores 1–3;
  `q3.f` suministra `e5.g.f3875e`, inicializado desde `user_id`.
- Código nativo ARM64 de `libLight.so`: sección `.main` y programa VM
  restaurados offline; se reconstruyeron `RequestTask.call`, `Light.Crack`,
  `DtApplication.onCreate` y el helper de descifrado.
- La respuesta se valida con cinco vectores sintéticos reproducibles de
  Java/JCE: catálogo de cadenas, catálogo de objetos compatible, interfaz,
  textos y lista vacía. El enlace sintético usa Base64 de UTF-8 en Java.
- 19 pruebas cubren conservación completa, 1.000 perfiles, errores, límites,
  CLI independiente y el contrato HTTP mediante mocks, incluido el uso de
  `user_id` en lugar de `token`. No envían identificadores al servicio.

Reproducir los vectores y ejecutar las pruebas:

```bash
java tests/golden/DTunnelModVectorGenerator.java > /tmp/dtunnelmod_vectors.json
python -m unittest tests.test_dtunnelmod
```

### Validación con el servicio real

El **18 de octubre de 2026, entre 22:39 y 22:40 UTC**, se consultaron los
tres selectores del endpoint original con autorización explícita del
usuario, usando `user_id` de la muestra. Los tres se descargaron y
descifraron correctamente con el script publicado, sin modificar el motor:

| Actualización | Respuesta Base64, bytes | JSON claro, bytes | Miembros recuperados |
| --- | ---: | ---: | ---: |
| `app_config` | 75.520 | 56.636 | 46 perfiles |
| `app_layout` | 47.488 | 35.602 | 37 ajustes de interfaz |
| `app_text` | 10.412 | 7.807 | 108 textos |

El catálogo y la interfaz contienen cadenas JSON; los textos contienen
objetos directos, como indicaba el análisis del cliente. Se compararon
todos los miembros y sus campos con los objetos del JSON descifrado.
El catálogo contiene 22 campos por perfil. La CLI sobre la respuesta
guardada recuperó los mismos 46 objetos completos que la API Python.

Una segunda implementación con OpenJDK/JCE descifró las tres respuestas
reales y produjo exactamente los mismos bytes de texto claro que Python.
SHA-256 de la respuesta cifrada del catálogo:
`448bcad1618dfded2aab71aa82f024cb33b65e8b699534b527ec9f73d41b57bc`.
SHA-256 de sus 56.636 bytes de JSON claro:
`4d49a034ad1b8020a68e714154fd7a9849b82cfce82fd7805ae32c47006692bd`.

Esto verifica la descarga y el formato de esas respuestas, no la conexión
VPN ni la disponibilidad de cada servidor. Las cantidades y el acceso
pueden cambiar; el formato CBC sigue sin ofrecer autenticación criptográfica.
Las pruebas automatizadas permanecen offline y usan solamente fixtures
sintéticos y mocks, sin depender del servicio ni de sus identificadores.

No se versionan el APK, `credentials.json`, identificadores reales,
respuestas privadas ni resultados del catálogo.
