# Speicers Pro VPN — build123 y compatibilidad histórica

## Estado actual — 2026-11-01

Se obtuvo y analizó **104.1.20/build123**, misma firma de distribución,
con un cambio real: el catálogo incluido usa **SPCF1**, firma RSA3072/SHA256,
HMAC-SHA256 → PBKDF2-SHA256/600000 → AES256-GCM. La actualización ahora usa
un manifiesto firmado y una segunda descarga vinculada por URL/tamaño/hash.
El lector/CLI y worker aceptan SPCF1 además de WakkoDev y el asset de glifos.

**73 servidores /799 campos interiores del incluido**, JSON entero igual a
JCA y worker aislado. **El remoto SPCF1 actual sigue pendiente:** el proxy
agotó el CONNECT antes de HTTP; no se obtuvo el manifiesto ni su archivo.
No se afirma una descarga nueva exitosa a partir del incluido o de mocks.

La fuente GitHub anterior se descargó realmente mediante el conector y abrió
completa: versión35/74 servidores/797 campos. Es **remoto histórico build120**,
no el feed del build123. El broker público preexistente conserva ese origen;
no se lo reemplaza ni se anuncia el nuevo antes de validar su descarga real.
Sin cambios de ficha/icono, C0240/C8255, fuente59/58 o Unlocked; el recuento41/42
que figura abajo es histórico. [Evidencia y siguiente paso](ANALYSIS.md).

La CLI sin entradas intenta el feed nuevo: GET a
`https://gen.spei.click/updates/servers.json`, después URL firmada exacta bajo
`/updates/servers/<version>/<sha256>.png`. Cabeceras de la app: Cache-Control
no-cache, Accept application/json en el primero y application/octet-stream en
el segundo; UA Android por defecto (el script emplea su prefijo Dalvik/2.1.0).
El script añade Accept-Encoding identity para limitar el transporte. Sin
sesión, renovación, body, cuenta o token adicionales en esta ruta del DEX.
TLS normal, sin redirecciones; límite16000 del manifiesto y3000000 del archivo.
No se consulta login, usuarios, pagos ni suscripciones.

```sh
# Feed actual: falla explícitamente si no obtiene el manifiesto firmado.
python server_catalog_decoder.py -o actual.json
# Separación explícita del origen histórico; nunca fallback automático.
python server_catalog_decoder.py --legacy-remote -o historico.json
# Incluido real del APK123, independiente del remoto.
python server_catalog_decoder.py --apk /privado/base.apk -o incluido-123.json
```

La exportación `.sks` sigue GCM/PBKDF2 y DES/XML como120. El código123 confirma
el esquema abierto: file.proteger=0, file.validade=0, bloquearRoot=0 y
file.pedirLogin=0, con los campos completos de Properties. **No hay muestra
`.sks` real de este build ni importación Android probada**; no se anuncia ni
se añade un escritor Unlocked como validado por esta investigación.

---

## Integración histórica del build120

Lector solicitado por el propietario de SP-DECODE. Descarga el catálogo
oficial de servidores y abre todos sus campos conocidos. Requiere Python 3 y
PyCryptodome; funciona sin root, Frida, emulador ni APK instalado.

**Ahora aparece en Server VPN por la instrucción posterior del usuario.** La
solicitud de incorporarlo junto con ANY VPN sustituye la exclusión inicial.
Tiene ficha, PNG original del APK y broker HTTPS fijo con control individual.
El catálogo SP-DECODE sube a versión mínima 41 y 42 fichas. Se conservan los
switches persistentes y no se realiza un despliegue automáticamente.

## Termux

`server_catalog_decoder.py` es autónomo: puede copiarse como `speicers_pro.py`.
No necesita las otras carpetas del repositorio.

```bash
pkg install python clang make curl
pip install pycryptodome==3.23.0
curl -fL 'https://raw.githubusercontent.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/fix/http-jireh-current-method/decoders/Python/apps/Speicers_Pro_VPN/server_catalog_decoder.py' -o speicers_pro.py
python speicers_pro.py -o servidores.json
```

El JSON se guarda completo, con permiso 0600, en un archivo **nuevo**. Si ya
existe, elegir otro nombre; nunca se sobrescribe. Ejecutar en `$HOME` de Termux
para conservar los permisos privados. Solo se imprime ruta, versión y conteo.
No publicar el JSON: contiene la configuración recuperada.

La descarga histórica usa un GET a una URL HTTPS fija recuperada del DEX, sin redirecciones,
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
