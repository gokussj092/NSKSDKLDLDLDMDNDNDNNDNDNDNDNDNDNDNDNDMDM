# Neutro Vpn 1.5 — .nvpnc, texto y catálogo firmado

Motor independiente: [`neutro_vpn.py`](../decoders/Python/neutro_vpn.py).
APK analizado: `base.apk` dentro de `base.zip`, paquete
**`com.neutrovpn.tech`**, nombre **Neutro Vpn**, versión **1.5**, build **6**.

## Métodos identificados

| Entrada | Formato comprobado | Soporte del script |
| --- | --- | --- |
| Archivo `.nvpnc` | Texto `NVPNC1.L` o `NVPNC1.P` | Descifrado y JSON completo |
| Perfil compartido o pegado | El mismo texto `NVPNC1.…` del archivo | `--text` o archivo local |
| Catálogo remoto | Tres campos Base64, firma ECDSA y AES-GCM | Verificación, descarga y JSON completo |
| Catálogo integrado | El mismo contenedor firmado dentro de `RemoteConfig` | Autenticado durante el análisis; no embebido en el script |
| Enlaces estándar | `vless`, `vmess`, `trojan`, `ss`, `hysteria`, `hysteria2`, `hy2` | Inspección de campos URI/Base64, conservando el original |
| JSON Xray | Objeto con `outbounds` | Lectura completa, sin transformación |

El exportador usa `CREATE_DOCUMENT`, extensión `.nvpnc` y MIME
`application/octet-stream`. Su opción de compartir usa `SEND text/plain`
con exactamente el mismo contenedor. El importador permite archivo o texto
pegado. No se identificó un esquema propio `neutro://`.

Los enlaces estándar pertenecen al editor Xray/Hysteria, no a una capa
adicional de cifrado de Neutro. El lector presenta sus campos y conserva
`raw`, parámetros repetidos, vacíos y desconocidos. En VMess Base64 conserva
todo el objeto JSON; en Shadowsocks abre Base64 de credenciales o del enlace
completo. Esta vista no genera la configuración de ejecución de Xray, no
valida plugins ni aplica sus valores predeterminados. Dentro de perfiles y
catálogos, `xray`, `capXray` y demás cadenas se mantienen tal como estaban.

## Uso

Python 3.10 o posterior y PyCryptodome. No necesita APK, Android, Java ni
bibliotecas nativas del APK para ejecutarse.

```bash
python -m pip install pycryptodome

# Archivo, con o sin contraseña original:
python decoders/Python/neutro_vpn.py perfil.nvpnc -o perfil.json
python decoders/Python/neutro_vpn.py perfil.nvpnc --ask-password -o perfil.json
python decoders/Python/neutro_vpn.py perfil.nvpnc --password-file clave.txt

# Perfil compartido, enlace estándar o JSON Xray:
python decoders/Python/neutro_vpn.py --text 'NVPNC1.L..NONCE.CONTENIDO'
python decoders/Python/neutro_vpn.py --text 'vless://id@example.invalid:443?security=tls'

# Descargar el catálogo real e imprimir todo el JSON:
python decoders/Python/neutro_vpn.py --url
python decoders/Python/neutro_vpn.py --url -o catalogo.json

# Endpoint explícito o respuesta cifrada ya guardada:
python decoders/Python/neutro_vpn.py --url https://raw.githubusercontent.com/DKARLTECH/notes/main/c.txt -o catalogo.json
python decoders/Python/neutro_vpn.py respuesta_catalogo.txt -o catalogo.json
```

La lista de perfiles permanece en `profiles`; también se conservan los
ajustes globales, versiones, avisos y campos futuros del documento raíz.
No hay límite fijo de miembros ni selección de solo los primeros perfiles.

`--ask-password` oculta la entrada. `--password-file` lee UTF-8 y retira
solo un LF o CRLF final; conserva espacios y otros caracteres de la
contraseña. Los perfiles `P` necesitan su contraseña original. Las
restricciones de móvil, root, caducidad y device ID son metadatos del JSON;
no intervienen en la derivación de la clave. El lector los conserva sin
ejecutar las políticas de importación de Android.

## Archivos NVPNC1

`ConfigPackager` (`e.java`) produce:

```text
NVPNC1.L..Base64(nonce12).Base64(ciphertext || tag16)
NVPNC1.P.Base64(salt16).Base64(nonce12).Base64(ciphertext || tag16)

L: key = clave compartida AES de 32 bytes del cliente
P: key = PBKDF2-HMAC-SHA256(UTF-8(contraseña), salt, 120000, 32 bytes)
plaintext = AES-256-GCM(key, nonce, sin AAD, tag de 128 bits)
resultado = JSON UTF-8(plaintext)
```

El exportador actual escribe `v=2` dentro del JSON, aunque el marcador
exterior sigue siendo `NVPNC1`. El script conserva todos los campos y no
reconstruye el objeto mediante la clase `Profile`, que descartaría campos
desconocidos y aplicaría defaults. Tampoco genera nuevos IDs, modifica
`unlocked` o recorta mensajes ya presentes en el archivo.

Se exigen las longitudes del exportador analizado: salt vacío en `L`,
16 bytes en `P`, nonce de 12 y tag de 16. No se ofrece una búsqueda de
contraseñas. Una contraseña ausente produce `PASSWORD_REQUIRED`; una clave
incorrecta o modificación del contenido autenticado produce `AUTH_FAILED`.

La clave compartida se reconstruye en `KeyMaterial` (`i.java`) concatenando
tres arrays XOR con `0x61`, `0xCB` y `0x9F`, y decodificando su Base64.
Es una constante del formato distribuida en todos los clientes, no una
credencial de cuenta. SHA-256 de sus 32 bytes:
`b1529ed4b40c495ad6e7fc9e977caf353eb97304efe5c7244633c8b020c045f6`.
La ofuscación StringFog usa Base64 y XOR repetido con `UTF-8`; protege
literales del código, no añade una capa a los archivos exportados.

## Catálogo remoto y autenticación

`RemoteConfig` (`s.java`) contiene estos endpoints en orden:

1. `https://neutro-config.hemdrova.workers.dev/c`
2. `https://raw.githubusercontent.com/DKARLTECH/notes/main/c.txt`

El flujo original realiza un GET con `User-Agent: NeutroVpn/1` y parámetros
`i=<UUID aleatorio de 32 caracteres hex>` y `b=6`. El UUID es un identificador
de instalación creado por la aplicación. El script genera uno nuevo por
invocación y lo reutiliza al intentar el respaldo. No necesita extraer un
token o un identificador privado del APK.

`--url` sin valor prueba esos endpoints hasta obtener una respuesta
autenticada. `--url URL` consulta únicamente la dirección explícita. Una
descarga fallida produce un error; el script no contiene el catálogo
integrado. Se permiten redirecciones HTTPS con un máximo de cinco;
no se acepta HTTP, URL con credenciales ni fragmentos. Timeout de 20
segundos por operación de socket y sin reintentos del mismo endpoint.

`ConfigCrypto` (`d.java`) interpreta:

```text
Base64(nonce12).Base64(ciphertext || tag16).Base64(firma_DER)
verificar SHA256withECDSA(public_key_P256, nonce || ciphertext || tag)
descifrar AES-256-GCM(clave compartida, nonce12, sin AAD, tag16)
interpretar el JSON UTF-8 completo
```

Se verifica primero la firma con la clave pública EC P-256 incluida en el
cliente y después GCM. No se incluye ninguna clave privada de firma ni se
permite omitir la verificación desde la CLI. La firma da autenticidad al
catálogo del proveedor; un perfil `L` utiliza únicamente la clave simétrica
compartida y GCM.

La aplicación compara la versión `v` con su caché y modifica algunos campos
al importar perfiles remotos. El script devuelve la respuesta autenticada
tal como está, sin fusionarla con cachés, renombrar IDs ni activar perfiles.

## Evidencia real y límites

- ZIP SHA-256: `ed780c893d292edd56d3f2b1b3db2d20f1eb276493670cf7f20fe12560d124e4`.
- APK SHA-256: `e46e79b3a5275bbda4c158d37090654593e6edcff3da880ffa101c61c1de69bd`.
- Código de la aplicación en `classes124.dex`; StringFog en `classes121.dex`.
- `ProfileDashboard` (`p.java`) confirma la extensión, los dos modos de
  exportación y los selectores de archivo/texto. `XrayConfig` (`ae.java`)
  y `Hysteria1` (`g.java`) confirman los enlaces estándar.
- El catálogo integrado se autenticó: 7.570 bytes de JSON, versión
  `1791975967`, diez perfiles de 21 campos cada uno.

El **18 de octubre de 2026, 22:46 UTC**, se consultaron y autenticaron
ambos endpoints originales con el flujo normal de la aplicación:

| Fuente | Respuesta, bytes | JSON claro, bytes | Versión `v` | Perfiles |
| --- | ---: | ---: | ---: | ---: |
| Worker principal | 7.510 | 5.529 | 1792355486 | 6 |
| Respaldo GitHub | 7.511 | 5.529 | 1792355486 | 6 |

La diferencia de un byte corresponde al LF final del respaldo. Sus JSON
claros son idénticos, con perfiles de 18 a 20 campos. Se conservaron todos
los valores y los ajustes globales. Una implementación independiente con
OpenJDK/JCE verificó ECDSA y GCM de las tres muestras reales y produjo los
mismos bytes claros que Python. La CLI `--url` también se verificó contra
la respuesta real completa. SHA-256 del JSON remoto de 5.529 bytes:
`ba1e2fbb23cecd4df24ac0f95a95b19fa03478da1ae998ea968b7a6318d6b8bd`.

Los seis perfiles son los devueltos por esos endpoints en esa consulta;
su cantidad puede cambiar. El catálogo integrado anterior contiene diez,
pero no debe confundirse con la actualización actual. No se verificó la
conectividad VPN de los servidores.

No se recibió una exportación `.nvpnc` de usuario. Los modos `L/P` se
validaron con vectores sintéticos independientes Java/JCE, incluida una
contraseña con espacios, Unicode y un carácter fuera del BMP. El productor
de fixtures usa un escalar de firma **conocido de pruebas**, valor 1, sin
relación con la clave privada del proveedor. La clave pública de producción
rechaza esas firmas sintéticas.

24 pruebas cubren integridad ECDSA/GCM, contraseña, JSON completo, 1.000
perfiles, URI, CLI independiente y descarga/respaldo con mocks:

```bash
java tests/golden/NeutroVpnVectorGenerator.java > /tmp/neutro_vpn_vectors.json
python -m unittest tests.test_neutro_vpn
```

## API y recursos

```python
from decoders.Python.neutro_vpn import decode, decode_profile, decode_catalog, download_catalog, run

perfil = decode_profile(contenido, password=contraseña_original)
catalogo = decode_catalog(respuesta_cifrada)
catalogo = download_catalog()  # única API de alto nivel que usa red
objeto = decode(archivo_o_texto)  # detección offline
texto_json = run(contenido)  # str o None; siempre offline
```

Límites: 32 MiB de entrada/respuesta, profundidad JSON 64, un millón de
nodos contando claves y contraseña de hasta 16.384 bytes UTF-8. El cliente
Android limita archivos y respuestas a aproximadamente 64 KiB; este lector
permite entradas mayores para análisis sin limitar el número de perfiles.
Se rechazan claves duplicadas, números no finitos y Unicode inválido.

CLI: salida JSON en stdout o `-o`; errores JSON en stderr, sin contraseñas
ni excepciones HTTP. Códigos 0 al completar, 1 por formato/autenticación/red
y 2 por argumentos o archivos. Se valida todo antes de escribir la salida;
un fallo de descifrado conserva el archivo anterior. Los errores del sistema
de archivos durante la escritura siguen siendo posibles.

Motor independiente, sin cambios en Android ni en el registro del bot.
No se versionan el APK, respuestas reales ni credenciales de servidores.
