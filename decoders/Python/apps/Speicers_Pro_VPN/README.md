# Speicers Pro VPN 104.1.17 (120)

Lector privado solicitado por el propietario de SP-DECODE. Descarga el catálogo
oficial de servidores y abre todos sus campos conocidos. Requiere Python 3 y
PyCryptodome; funciona sin root, Frida, emulador ni APK instalado.

**No aparece en Server VPN.** Solo se registra en el worker interno de lectura
offline; no tiene ficha, icono público ni broker web de descarga. El catálogo
SP-DECODE permanece en versión mínima 40 y 40 fichas. Activar el interruptor
global o pasar disponibilidad para este ID no puede añadirlo a la lista. No se
modifican los controles persistentes ni se realiza un despliegue.

## Termux

`server_catalog_decoder.py` es autónomo: puede copiarse como `speicers_pro.py`.
No necesita las otras carpetas del repositorio.

```bash
pkg install python clang make curl
pip install pycryptodome==3.23.0
curl -fL 'https://raw.githubusercontent.com/Gh0stDeveloper/SP-DECODE/feat/mm-tunnel-1-10-11-1-decoders/decoders/Python/apps/Speicers_Pro_VPN/server_catalog_decoder.py' -o speicers_pro.py
python speicers_pro.py -o servidores.json
```

El JSON se guarda completo, con permiso 0600, en un archivo **nuevo**. Si ya
existe, elegir otro nombre; nunca se sobrescribe. Ejecutar en `$HOME` de Termux
para conservar los permisos privados. Solo se imprime ruta, versión y conteo.
No publicar el JSON: contiene la configuración recuperada.

La descarga usa un GET a una URL HTTPS fija recuperada del DEX, sin redirecciones,
sin parámetros de ubicación arbitraria y con límite de 8 MiB / 25 segundos.
No envía datos personales ni cambia el servidor. No obtiene listas de usuarios,
no inicia sesiones y no llama a los endpoints de pagos o activación de cuentas.
Los controles recibidos se preservan como datos, sin modificar su valor.

## Copias locales y assets

```bash
python speicers_pro.py --input copia-cifrada.txt -o copia-abierta.json
python speicers_pro.py --apk base.apk -o incluido.json
python speicers_pro.py --apk base.apk --asset config/config.json -o secundario.json
```

`--apk` requiere el APK principal extraído del APKS. El asset predeterminado es
`flags/config.png`: pese a su nombre, contiene texto cifrado, no una imagen.

| Fuente real verificada | Versión | Servidores |
|---|---:|---:|
| `assets/flags/config.png` | 36 | 75 |
| Respuesta oficial `servidores_pro` | 35 | 74 |
| `assets/config/config.json` secundario | 9 | 32 |

El remoto observado es anterior al incluido. El script entrega la respuesta
remota exacta que recibe, sin mezclar, sustituir ni afirmar que sea más reciente.
Conserva todos los registros, orden, claves originales, booleanos, campos extra
y ajustes de habilitación. Los nombres opacos de las claves no se renombraron;
`FIELD_NAMES` documenta su significado y distingue el booleano `OtrasConfigs`.

## Archivos, contraseña, texto y cloud

El DEX conserva importador/exportador `.sks`: AES-128-GCM con PBKDF2-HMAC-SHA256
y compatibilidad histórica DES/XML. Los parámetros coinciden con el lector
canónico existente, que se reutiliza en `file_decoder.py`; las rutas y el
conteo C0/C8 no cambian. Sin una exportación real aportada ni ejecución Android,
no se afirma haber comprobado la interfaz de exportación de este build.

Desde un checkout completo:

```bash
python decoders/Python/apps/Speicers_Pro_VPN/file_decoder.py perfil.sks > perfil.json
```

Ninguna de estas rutas criptográficas requiere una contraseña introducida por
el usuario. Los datos de login/PAM y controles de conexión del catálogo tienen
otra función y se conservan. No se identificó un formato propietario de texto
ni intercambio de perfiles cloud por token. El esquema `speicerspro://payment`
es un retorno de pago, no un perfil VPN. Sí se identificó actualización remota
del catálogo y una fuente separada de usuarios; esta última no se descarga ni
se registra como parte del nuevo lector.

Las dos capas de catálogo usan CBC sin MAC: padding y estructura estrictos
detectan errores, pero no prueban autenticidad criptográfica de una respuesta
manipulada. HTTPS se valida normalmente. `.sks` GCM sí verifica su tag.

Ver [ANALYSIS.md](ANALYSIS.md) y [TESTING.md](TESTING.md) para evidencia y límites.
