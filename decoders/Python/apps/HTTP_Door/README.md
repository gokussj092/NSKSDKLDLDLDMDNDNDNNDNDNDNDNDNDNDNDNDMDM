# HTTP Door 5.0 (5)

Paquete `com.httpdoor.vpn`. Lector offline de **`.kyz`** integrado en Cloud C8
y el bot del PR #99. No se identificó un catálogo de servidores en el APKS
analizado; no se registra proveedor, ficha o descarga remota por inferencia.

## Uso en el repositorio

Python 3.10+, `pip install -r requirements.txt` de esta carpeta:

```sh
python file_decoder.py perfil.kyz --output perfil.json
python file_decoder.py - < perfil.kyz
```

La salida conserva `raw_xml` exacto, todas las `entries` ordenadas, duplicados,
vacíos, Unicode, campos desconocidos y el mapa `properties` con el último
valor de cada clave, como Java. No renombra claves ni convierte indicadores.
El parser XML canónico se reutiliza de CREEB INJECTOR, sin usar su clave DES
ni admitir sus bundles JSON. No acepta Base64 o GCM como variantes de `.kyz`.

## Script autónomo para Termux

`http_door.py` es la copia autónoma generada y comprobada. Para reproducirla
en una ruta nueva con el mismo parser compartido:

```sh
python scripts/apk_analysis/http_door_bundle.py /ruta/http_door.py
```

La salida debe ser una ruta nueva. En Termux, con el script descargado:

```sh
pkg install python clang make
python -m pip install pycryptodome==3.23.0
python http_door.py perfil.kyz --output perfil.json
```

No requiere APK, root, contraseña ni conexión de red. `--output` crea un archivo
0600 y rechaza sobrescritura; sin esa opción imprime el JSON completo. No es
un descargador de servidores: este APK no aporta una fuente identificada.

## Método y límites

`ConfigParser` exporta `Properties.storeToXML` y cifra bytes directamente con
`Cripto`, `DESKeySpec("cinbdf665$4")`, `Cipher.getInstance("DES")`: DES-ECB,
padding PKCS5 y los primeros ocho bytes `cinbdf66`. No hay IV ni sobre Base64.
`convertInputAndSave` descifra y carga XML antes de comprobar versión, fecha,
root, operador o HWID. `file.pedirLogin` se refiere al acceso al túnel; no es
una contraseña criptográfica del archivo. Se conservan todas esas restricciones.
El AES de SecurePreferences protege el almacenamiento local y no este export.

Hasta 8 MiB de entrada/salida en el lector; el worker conserva su límite común
de salida de 4 MiB y rechaza excesos sin devolver éxito parcial. Padding y XML
se validan, se rechazan entidades y DTD ajenos al estándar Java; no se consultan
DTDs. DES no autentica el contenido: estas validaciones no constituyen un MAC.

Tres documentos sintéticos íntegros comparados con JDK, CLI, worker y script
autónomo. **Pendiente exportación `.kyz` real y ejecución Android/Termux.**
Se publica el formato como Cloud, sin añadir soporte Android offline.
Ver `ANALYSIS.md`, `TESTING.md` y `manifest.json`.
