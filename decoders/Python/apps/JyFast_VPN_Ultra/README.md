# JyFast VPN Ultra 9

Paquete `http.jyfast.vpnultra`, desarrollador Prominex. Se analizó la versión
**9 / versionCode 9**, descargada de APKPure el **2026-10-31**. La ficha consultada
anuncia una versión 10, pero el archivo obtenido del espejo sigue siendo 9:
**no se certifica la versión 10**. El APK no se incluye ni se necesita para usar
los lectores. La integración continúa en `fix/http-jireh-current-method`.

## Uso

Python 3.10 o posterior y `pip install -r requirements.txt`. Desde esta carpeta:

```bash
python server_catalog_decoder.py > gratuito.json
python server_catalog_decoder.py --mode premium > premium.json
python server_catalog_decoder.py copia_cifrada.txt --mode free > catalogo.json
python server_catalog_decoder.py --stdin --mode premium < copia_cifrada.txt
python file_decoder.py perfil.sks > perfil.json
python file_decoder.py < perfil.sks > perfil.json
```

Sin archivo ni `--stdin`, el catálogo descarga exclusivamente la fuente fija del
modo elegido; el modo predeterminado es `free`. Archivo y stdin funcionan sin
red. Se requiere la carpeta hermana `HTTP_FenixVPN/` con `codec.py` y
`field_names.json`, que aportan validación y el importador SKS compartido.

## Método confirmado en el APK

`Rt.a/b` contiene el método de catálogo. El contenedor usa el alfabeto
`!?-=∆×÷ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`:
los índices **0 a 64** se convierten al alfabeto Base64 estándar, incluido `=`.
Los seis símbolos sobrantes no son válidos. Después se aplica AES-256-CBC con
padding PKCS5/PKCS7, IV de 16 ceros y clave **SHA-256 de los bytes UTF-8 de la
contraseña**, sin conversión hexadecimal ni PBKDF2.

- Gratuito: constante `JyFastv1c2`.
- Prémium: constante `Jyfastv1c`.
- Los 22 campos enumerados en `codec.SERVER_FIELDS` usan el mismo método con
  `Key: =Kenova_code`. Incluyen SSH, proxy, payload, SNI, SlowDNS, UDP, V2Ray,
  DNSTT, FastDNS y buffers HTTP.

Solo se descifran esos campos conocidos. Nombres, puertos, indicadores,
estructuras desconocidas y campos vacíos conservan sus claves, tipos y valores.
Se devuelve el documento entero; no se recorta al primer perfil.

Las cadenas de `ConfigUpdate` están protegidas con SCKIT VMP. Se recuperaron
mediante el ARM64 y el asset originales, usando
`scripts/apk_analysis/jyfast_vmp_strings.py`. El sondeo fija los hashes del
nativo y del asset y modela JNI/Context, asignación de memoria y lectura del
asset. La creación de hilos se registra sin ejecutar su código. Es evidencia
de recuperación de constantes, **no una ejecución completa de Android**.

## Fuentes remotas

`ConfigUpdate.doInBackground` realiza GET con `X-IGNIX-SIG` igual al SHA-1
público del certificado firmante del APK. Las dos fuentes comprobadas son:

- `http://dev.jenrri.shop:85/ignix_update.php?cfg=free`
- `http://dev.jenrri.shop:85/ignix_update.php?cfg=premium`

El encabezado es `10c7440b8feac5cee6a54959e7599ff26bd27153`. Estas respuestas
no requirieron registro de dispositivo ni una sesión de usuario. El APK usa
HTTP en el puerto 85: el broker permite esa excepción solo para este proveedor
y estas rutas fijas, valida y fija una IPv4 pública y rechaza toda redirección.
Los demás proveedores conservan su política HTTPS. El CLI limita la respuesta
a 8 MiB, 25 segundos, HTTP 200 y contenido sin compresión; tampoco sigue
redirecciones ni recibe URLs del usuario.

El modo `custom` respondió **404** en su ruta original. No se publica ni se
reemplaza por otra fuente. Los assets `config.json`, `config.mvgl` y
`config.mvgm` no pasaron la validación con las claves de los modos remotos:
su descifrado sigue pendiente y no se usa como fallback.

## Archivos .sks

`ConfigImportFileActivity` selecciona la extensión `.sks` y delega en `r6.b`.
El DEX confirma el importador ya disponible en HTTP FenixVPN:

1. `Base64(salt32).Base64(nonce12).Base64(ciphertext+tag16)`,
   PBKDF2-HMAC-SHA256 con `fubvx788b46v`, 1000 iteraciones, clave de 128 bits,
   AES-GCM sin AAD.
2. Variante antigua DES-ECB/PKCS5; `DESKeySpec` toma los primeros ocho bytes
   de `cinbdf665$4`, es decir `cinbdf66`.

Se reutiliza el motor y la ruta SKS existentes. La salida conserva entradas
Java Properties ordenadas, claves duplicadas, vacíos, saltos de línea y
`raw_xml`. Se probaron vectores sintéticos GCM/DES; **no se obtuvo una
exportación real de JyFast ni se certifica su exportador**. No se identificó
un esquema propio de enlaces que justifique añadir otro lector.

## Integración y comprobaciones

Cloud añade la tarjeta y el control individual `jyfast-vpn-ultra`, el icono
original y el catálogo público mínimo **57** (50 tarjetas). El broker descarga
ambas fuentes y entrega un lote `spdecode-jyfast-vpn-ultra-catalogs-v1` al
worker sin red. `run(data: bytes) -> str` acepta ese lote o una respuesta
gratuita individual. La salida del lote contiene `provider`, `complete: true`
y los documentos separados `catalogs.free` / `catalogs.premium`; si falla una
fuente, falla el lote completo. El gateway verifica que ambos documentos
estén presentes y coincidan con `rawText`.

Última captura del 2026-10-31: gratuito versión **33**, **44 servidores** y
**387 campos cifrados**; prémium versión **27**, **49 servidores** y
**400 campos cifrados**. Los documentos enteros coinciden entre JCA, Python,
CLI real y worker aislado: **93 servidores / 787 campos**, `isPartial=false`.
Durante el trabajo el gratuito cambió de 32/43 a 33/44; los recuentos son una
observación, no una constante del lector.

Pasaron **23 pruebas Python** (10 nuevas y 13 de regresión Jireh) y
**132 pruebas Node** dirigidas a descarga, catálogos, contratos y controles.
No se ejecutó la suite completa, una conexión VPN en teléfono ni un despliegue
VPS. La red real se comprobó con el CLI Python; el transporte Node se comprobó
con dobles de DNS/HTTP, sin quitar las restricciones de red del entorno.
Ver `TESTING.md` y `manifest.json` para reproducir y revisar el alcance.

El icono se conserva sin modificar: `res/drawable/nezu.png`, 512×512,
83968 bytes, SHA-256
`05e176023754019f84135e0247d0db91370a450536ddbc7b035c626e0a094ae8`.
Catálogos y salida del lector: máximo 8 MiB; archivos: 5 MiB; profundidad: 64.
El gateway mantiene su límite existente de 4 MiB para `rawText` de este
proveedor. Se rechazan JSON ambiguo, padding inválido y GCM alterado. Los
errores no imprimen configuraciones. Git contiene solamente código, iconos y
vectores sintéticos, sin APKs, catálogos reales ni credenciales descifradas.
