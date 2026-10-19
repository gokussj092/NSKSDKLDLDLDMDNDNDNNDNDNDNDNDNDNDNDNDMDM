# 24clan VPN Green 3.3

<img src="24clan_VPN_Green.png" width="96" alt="24clan VPN Green">

Paquete analizado: **`com.tcodes.green`**, versión **3.3**, build **25**.
Esta carpeta reúne los lectores y el icono de la aplicación. Los espacios
del nombre se representan con guiones bajos en los nombres de archivo.

| Archivo | Uso |
| --- | --- |
| [24clan_VPN_Green.py](24clan_VPN_Green.py) | Exclusivamente catálogo: respuesta local o descarga HTTPS |
| [24clan_VPN_Green_archivos.py](24clan_VPN_Green_archivos.py) | Exclusivamente archivos `.green` y su contenido cifrado como texto |
| [24clan_VPN_Green.png](24clan_VPN_Green.png) | Icono original extraído del APK, 512 × 512, sin modificaciones |

Los dos scripts funcionan por separado y no necesitan el APK. El lector
de archivos usa solo la biblioteca estándar de Python; el de catálogo
necesita además PyCryptodome. Requieren Python 3.10 o posterior.

## Catálogo

Desde esta carpeta:

```bash
python -m pip install pycryptodome

# Descargar e imprimir el catálogo completo:
python 24clan_VPN_Green.py --url
python 24clan_VPN_Green.py --url -o catalogo.json

# Respuesta cifrada o JSON del catálogo guardado previamente:
python 24clan_VPN_Green.py respuesta_catalogo.txt -o catalogo.json

# Otra URL explícita, con el mismo formato:
python 24clan_VPN_Green.py --url HTTPS_URL -o catalogo.json
```

`--url` sin valor consulta el endpoint original que usa `MainActivity`:

```text
https://24clanvpn.com/updater/6d5d4a5fb3d053300c1a89f85dbf05
```

La aplicación utiliza `y8.j` y un GET mediante `HttpURLConnection`, sin
token ni sesión de usuario en esta petición. El script usa GET y
`User-Agent: 24clan VPN Green/3.3`, validado con el servicio real. Solo
`--url` y `fetch_catalog()` usan la red. Las funciones `decode()` y `run()`
siempre procesan datos locales. No se incorpora el catálogo integrado
como respuesta de respaldo.

El resultado conserva el objeto raíz completo: `Version`, `Message`,
`WSDomain`, `Servers`, `PremiumServers`, `Tweaks`, `PremiumTweaks` y campos
futuros. No se fusionan ni recortan listas. Un tweak es una configuración
de conexión/payload; **no equivale a un servidor adicional**.

### Cifrado del catálogo

`z8.a.a()` lee el contenido de SQLite y llama a `g9.g.a()`. La actualización
remota llama al mismo descifrado desde `nc.y.b()`:

```text
raw = Base64 estándar(respuesta)
raw = "Salted__" || salt8 || ciphertext
D0 = vacío
D1 = MD5(D0 || ASCII("mtscrypt") || salt8)
D2 = MD5(D1 || ASCII("mtscrypt") || salt8)
D3 = MD5(D2 || ASCII("mtscrypt") || salt8)
key = primeros 32 bytes de D1 || D2 || D3
iv  = siguientes 16 bytes
JSON UTF-8 = AES-256-CBC-PKCS#7(key, iv, ciphertext)
```

Corresponde a `OpenSSL.decrypt("aes256", "mtscrypt", ...)` de
`org.apache.commons.ssl`, derivación EVP_BytesToKey/MD5 de una iteración.
La contraseña es una constante compartida del formato del cliente, no
una credencial de cuenta. Se admite también el objeto JSON sin cifrar,
que la rutina original devuelve sin cambios tras fallar OpenSSL.

El formato CBC no contiene MAC ni firma. Padding y JSON válidos no prueban
autenticidad criptográfica. Un fallo se informa como error; no se entrega
una lista vacía o un resultado parcial como si el catálogo se hubiera leído.

## Archivos y texto .green

```bash
python 24clan_VPN_Green_archivos.py perfil.green
python 24clan_VPN_Green_archivos.py perfil.green -o perfil.json
python 24clan_VPN_Green_archivos.py --text 'BASE64_DEL_ARCHIVO_GREEN'
```

Este script no tiene opciones de descarga ni depende del lector de
catálogo. Acepta el contenido Base64 del archivo como texto local; no se
identificó un esquema propio `green://` de intercambio. Los URI VPN y
configuraciones WireGuard/Xray presentes en campos del JSON se conservan
en sus cadenas originales, sin ejecutar conexiones ni adivinar cifrados.
Los objetos con servidores o tweaks agrupados también se devuelven completos;
no se aplican las fusiones ni marcas que Android añade al importarlos.

El exportador de `a9.a0.S()` añade metadatos, llama a
`k8.l.q(json, "technore_008515")` y guarda UTF-8 como `.green` mediante
`CREATE_DOCUMENT`. La importación llama a `k8.l.m` desde `MainActivity`,
`SplashActivity`, `ServersActivity` y `TweaksActivity`.

### Variante XXTEA del archivo

- Base64 estándar, sin cabecera propia.
- Clave compartida `technore_008515`, 15 bytes UTF-8, completada con cero
  hasta 16 bytes.
- Palabras de 32 bits little-endian; última palabra con la longitud original.
- `rounds = 6 + floor(52 / número_de_palabras)`.
- **Delta `-1704280`, equivalente a `0xFFE5FEA8`**. La constante habitual de
  XXTEA no reproduce este formato.
- Sumas, restas y desplazamientos reproducen los enteros Java de 32 bits.
- Tras descifrar se valida la longitud interna y se interpreta el JSON UTF-8.

Las funciones `k8.l.a/p/l/X/Y` confirman el mezclador, el padding de clave
y el tratamiento de longitud. El formato tampoco tiene MAC ni firma.
La longitud interna y el JSON permiten detectar errores estructurales;
no constituyen autenticación.

Se preservan `HWID`, `ExpireDate`, `MobileData`, `BlockRoot`, `isPremium`,
`Note`, `exported_custom_server`, `Server` y campos desconocidos. Los
controles de dispositivo, fecha y root se realizan en Android después
del descifrado; no participan en la clave y no se ejecutan en el lector.
No hay contraseña de usuario en el flujo de exportación identificado.
Si `Server` es una cadena JSON, permanece como cadena, conservando todos
sus valores. Tampoco se alteran payloads, certificados ni CRLF.

## Comprobación con datos reales

El **18 de octubre de 2026, 23:06 UTC**, se descargó el endpoint original
y se recuperó el catálogo completo, versión **1.5**:

| Lista | Catálogo remoto 1.5 | Integrado en APK, versión 1.4 |
| --- | ---: | ---: |
| `Servers` | 4 | 6 |
| `PremiumServers` | 2 | 13 |
| `Tweaks` | 1500 | 1504 |
| `PremiumTweaks` | 20 | 20 |

El remoto contiene **seis servidores y 1.520 tweaks**; el integrado,
19 servidores y 1.524 tweaks. Estas cifras son las observadas en las
muestras y pueden cambiar. El script descarga la respuesta actual, sin
sustituirla por el contenido integrado del APK.

La respuesta remota ocupa 705.580 bytes y produce 515.590 bytes de JSON.
El catálogo integrado ocupa 819.973 bytes y produce 606.969 bytes claros.
Se compararon todos los campos de ambos documentos. La CLI `--url` también
se ejecutó contra el servicio real y produjo el mismo catálogo completo.
OpenJDK/JCE descifró ambas muestras independientemente y generó exactamente
los mismos bytes claros que Python. No se probaron conexiones VPN.

SHA-256 del JSON remoto:
`73d084264a9bb476e2f692b0e25e70827e17c2519bca4a37f4d503e3af58578a`.

No se adjuntó una exportación `.green` real. Ese lector se validó con
vectores Java independientes que reproducen la variante del APK, incluidos
Unicode, CRLF, mensajes, servidor anidado y todos los restos de longitud
módulo cuatro. Se incluyen también objetos pequeños para comprobar las
distintas cantidades de rondas. El productor combina ese código Java con
JCE para el catálogo; solo utiliza datos sintéticos.

## Pruebas y procedencia

Desde la raíz del repositorio:

```bash
java tests/golden/Clan24GreenVectorGenerator.java > /tmp/clan24_green_vectors.json
python -m unittest tests.test_clan24_green
```

21 pruebas cubren ambos formatos, separación de los lectores, icono,
conservación completa, límites, CLI independiente y descarga con mocks.
Se probaron listas de 1.000 servidores y 2.000 tweaks sin truncamiento.

- ZIP recibido: `a527be57baec21504df80e091b0cc16516b5c9d02b7739db9008a42665b4f2a8`.
- APKS: `932bd68fe9eb35ce5d7ac7b59bb272c20ff10136854140b020649b4d42058b3f`.
- APK base: `f57d84aef2361de4ec856c3f973253bc13f3ed60bc9caa1cbc3c48067f7fa062`.
- Icono: `base.apk/res/drawable/ic_launcher.png`, copiado sin recodificar.
- SHA-256 del PNG: `ab923a12fe537a3b3bfe131f2c3b3c77a13d0439c2ab1ce94701f787423ffedb`.

## Contrato de salida

Ambos módulos exponen `decode(bytes_o_texto) -> dict` y `run(...) -> str | None`.
La CLI imprime JSON completo o usa `-o`. Errores JSON en stderr: código 1 por
formato/descifrado/red, 2 por argumentos o archivos y 0 al completar. Se
valida toda la entrada antes de escribir; un fallo de descifrado conserva
la salida anterior. Siguen siendo posibles errores del sistema de archivos
durante la escritura.

Límites: 32 MiB de entrada/respuesta, profundidad JSON 64 y un millón de
nodos contando claves. Se rechazan claves duplicadas, números no finitos,
Unicode inválido y listas de catálogo con miembros de tipos inesperados.
HTTP exige HTTPS, permite hasta cinco redirecciones HTTPS y usa timeout de
20 segundos por operación de socket, sin reintentos automáticos.

No se versionan APK, respuestas reales ni credenciales de servidores.
No se modifica Android ni el registro del bot. Las pruebas automatizadas
usan fixtures sintéticos y no dependen de la disponibilidad del servicio.
