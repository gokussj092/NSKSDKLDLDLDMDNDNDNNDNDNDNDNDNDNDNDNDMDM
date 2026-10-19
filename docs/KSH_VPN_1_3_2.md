# KSH VPN 1.3.2 — decodificador Python del catálogo

`decoders/Python/ksh_vpn.py` recupera el JSON completo de configuraciones
del catálogo cifrado utilizado por **KSH VPN 1.3.2**, paquete
`com.kshvpnteam.yannaing`, versionCode **2024**.

## Uso

Dependencia, ya incluida en los requisitos de SP-DECODE:

```bash
python -m pip install pycryptodome==3.23.0
```

Decodificar una copia local del catálogo:

```bash
python decoders/Python/ksh_vpn.py servers.json -o ksh_decoded.json
```

Descargar explícitamente el catálogo público referenciado por el APK y
guardar el resultado:

```bash
python decoders/Python/ksh_vpn.py --url -o ksh_decoded.json
```

También se puede indicar una URL HTTPS:

```bash
python decoders/Python/ksh_vpn.py --url https://raw.githubusercontent.com/yannaing86tt/ksh_server/main/servers.json -o ksh_decoded.json
```

Sin `-o`, imprime únicamente el JSON resultante en stdout. La ruta local
no necesita red. La descarga usa un timeout de 20 segundos, un límite de
16 MiB y no sigue redirecciones. Los errores van a stderr como JSON:
retorno **1** para errores de formato, autenticación o descarga, **2** para
uso incorrecto o errores de lectura/escritura y **0** en éxito.

Reutilización desde Python:

```python
from pathlib import Path
from decoders.Python.ksh_vpn import decode, run

raw = Path("servers.json").read_bytes()
catalog = decode(raw)       # dict completo; lanza DecodeError en fallo
formatted = run(raw)        # JSON str en éxito; None en fallo
```

## Formato comprobado

El documento de transporte es un objeto JSON con un campo `enc`:

```json
{"enc": "BASE64_DEL_CONTENEDOR"}
```

El script también acepta directamente el valor Base64 de ese campo,
incluyendo saltos de línea y un BOM UTF-8 exterior.

| Componente | Parámetro verificado |
|---|---|
| Biblioteca del APK | `lib/arm64-v8a/libapp.so` (Flutter/Dart AOT) |
| Referencia del catálogo | `package:vpn_one_tap_app/services/github_catalog.dart` |
| Endpoint público | `https://raw.githubusercontent.com/yannaing86tt/ksh_server/main/servers.json` |
| Espejo presente en el APK | `https://cdn.jsdelivr.net/gh/yannaing86tt/ksh_server@main/servers.json` |
| Contenedor binario | `nonce[12] || ciphertext || tag[16]` |
| Cifrado | AES-256-GCM, sin AAD |
| Clave | 32 bytes; Base64 estático embebido en el APK |
| Ubicación de la cadena Base64 | offset de archivo `0x71736` en el `libapp.so` analizado |
| Texto autenticado | UTF-8, JSON raíz con `servers` como array de objetos |

La clave de compatibilidad procede del cliente distribuido y se conserva
en el motor como material del formato. No es un token de cuenta.

Se verifica GCM **antes** de interpretar o devolver contenido. No se
prueban contraseñas de otras familias. El resultado preserva el orden y
todos los campos, incluidos los desconocidos, estructuras anidadas,
valores nulos, puertos, flags, enlaces `accessUrl`, campos SSH y DNSTT.
No transforma los enlaces de conexión ni filtra servidores.

## Evidencia de validación

Análisis realizado el **18 de octubre de 2026**, desde el ZIP aportado.

| Artefacto | SHA-256 |
|---|---|
| APK 1.3.2 | `5e82e75ea5607e0a8c413d46930e61ae856f075c0186bfa620520cabee3fa2ba` |
| `libapp.so` | `528ec4eb54c4ee7163212500322c3f7ea4e9ee7b0da75df608a038a6fa2a06ab` |
| Catálogo cifrado consultado | `7e51e75b3a27a69b2b516672e8e6443d597ee180f534e36007ee0d5e659bb3d4` |

El catálogo corresponde al blob público GitHub
`aef9860e188b98ac222d3b5290802654867ed967` del repositorio
`yannaing86tt/ksh_server`. Se obtuvo **autenticación GCM válida** y un JSON
de **tres servidores**, comparado íntegramente con el resultado del script.
La validación no estableció conexiones VPN ni comprobó disponibilidad de
los servidores. El APK y el catálogo real, cifrado o descifrado, no se
incluyen en Git.

Las pruebas versionadas usan exclusivamente datos ficticios y dominios
`.invalid`. El vector congelado fue producido independientemente con
`cryptography.hazmat.primitives.ciphers.aead.AESGCM`; el decodificador usa
PyCryptodome. Se comprueban alteraciones de nonce/ciphertext/tag, clave y
AAD incompatibles, JSON inválido, límites, salida CLI y descarga explícita.

```bash
python -m unittest tests.test_ksh_vpn -v
python validate_project.py
python -m unittest discover -s tests -v
```

## Alcance de esta rama

La ruta comprobada del APK es el catálogo de servidores. No se encontró
evidencia de una extensión exportable `.ksh`: no se inventa una extensión
ni se registra `.json` como formato genérico del bot.

Las rutas Worker autenticadas `auth/firebase/servers-v2` son un flujo
distinto y no están certificadas por esta muestra. El script no inicia
sesión ni incorpora credenciales de cuenta. Un cambio de clave o
contenedor en otra versión requerirá una nueva muestra para validarlo.

Se entrega un motor Python independiente. No modifica el registro del
bot, la aplicación Android, otros descifradores ni versiones de release.
