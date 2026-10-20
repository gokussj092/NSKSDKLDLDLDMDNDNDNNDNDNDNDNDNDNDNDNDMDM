# Verificación — HTTP Custom build 899

Fecha: 2026-10-20. Python 3.12, PyCryptodome 3.23.0 y argon2-cffi 25.1.0.
La versión analizada es el APK aportado **7.11.28 - Patch 1 (899)**; no se
certifica que sea la última versión publicada de la aplicación.

## Muestras reales autorizadas

Se recuperaron seis exportaciones originales de esta versión. No se
publican sus contenidos ni sus credenciales. El lector HCCFG anterior
rechazaba los seis contenedores exteriores.

| Protección de las muestras | Cantidad | Resultado |
| --- | ---: | --- |
| Sin credenciales, con/sin bloqueo visual de payload | 2 | HCX4, sección principal, ambas secciones de perfiles y ambas capas HPR1 autenticadas; cuatro HPC1 completos |
| Contraseña, con/sin bloqueo visual de payload | 2 | HCCFG 10/n11 completo con la contraseña original: principal y cuatro perfiles HPC1/HPR1 autenticados; sin contraseña se solicita y una contraseña incorrecta se rechaza |
| HWID, con/sin bloqueo visual de payload | 2 | HCCFG 10/n12 completo con el HWID original: dos slots, principal y cuatro perfiles HPC1/HPR1 autenticados; sin HWID se solicita y un HWID incorrecto se rechaza |

Para las seis exportaciones completamente abiertas se compararon todos los
campos de HPC1 con el parser histórico independiente de once campos, el
JSON principal con una apertura de referencia separada y el envelope
completo con la apertura independiente HCX4. Se conservan los textos de
opciones y sus valores JSON. El script CLI `HTTP_Custom.py`, la API `run`
y el proceso aislado Cloud devolvieron el mismo objeto completo;
`isPartial=false` en los seis casos reales. Total: **12 perfiles HPC1**, sus
12 capas HPR1 y seis secciones principales autenticados. En los dos archivos
n12 se abrió un slot de clave HWID por archivo.

Las credenciales originales aportadas por el usuario permitieron completar
los cuatro casos protegidos pendientes. La verificación de referencia
derivó Argon2id directamente con `argon2.low_level`, reconstruyó el transcript,
abrió los slots HWID y autenticó cada capa antes de comparar los campos.
Ambos lanzadores recibieron las credenciales por stdin; Cloud utilizó su
canal de credenciales existente. **No fue necesario modificar el motor.**
No se publica ningún valor de contraseña/HWID, perfil o JSON real descifrado.
Ninguna de las seis muestras combina contraseña y HWID a la vez: el doble
bloqueo continúa cubierto por los vectores sintéticos nativos, no por una
exportación real de doble bloqueo.

## Contraste con código nativo

Se identificó el codec exterior en `U9085043933007906326`, el orden real
HCX4/HCX3/HCX2/HCX1 en su enum y la selección de familia 4 para n11/n12 en
`N1319217069659000081`. Las funciones de `libruntime.so` `0x1d63f0` y
`0x1e6ab0` se ejecutaron con Unicorn usando exclusivamente datos públicos
sintéticos y un contexto de certificado modelado.

Se capturaron cuatro claves de derivación independientes del código Python:
sin bloqueo, contraseña, HWID y ambos. Las claves esperadas están en
`tests/golden/http_custom_899.py`; las muestras sintéticas se cifran con
ellas, sin usar `codec.derive` para generar la respuesta esperada.
El vector HMAC/prestate y la clave exterior también tienen respuestas
fijas conocidas. La autenticación de los seis archivos reales valida el
uso del certificado y los estados recuperados para HCX4.

La emulación fue una herramienta de análisis con entorno Android modelado,
no una ejecución de importación/exportación en un teléfono. No forma parte
del lector entregado. Las tentativas de usar la antigua derivación SHA-256
normal fallaron; no se incorporan como fallbacks.

## Regresión automatizada

Desde la raíz del repositorio:

```sh
python -m pip install -r requirements.txt
python -m unittest tests.test_http_custom_899 tests.test_hc_sip_new_variants tests.test_cloud_c2_hc tests.test_cloud_c0_inventory -v
PYTHONPATH=cloud/workers/python:. python -m unittest discover -s cloud/workers/python -p 'test_*.py' -v
```

Resultado: **33 pruebas satisfactorias** en el primer comando, incluidas
**9 pruebas nuevas**, y **11 pruebas satisfactorias** del worker.

Cobertura nueva:

- Las cuatro combinaciones de credenciales contrastadas con la KDF nativa;
  HWID normalizado y selección entre varios slots.
- Igualdad completa de perfiles, principal, opciones anidadas, campos
  desconocidos, nulos, booleanos, vacíos, flags y fecha de 64 bits.
- Bytes binarios y una/dos conversiones UTF-8/Latin1; Unicode y CR/LF.
- Sidecars binarios y texto que se parece a un literal JSON, sin cambiar
  su tipo; secciones adicionales.
- Rechazo independiente de tag exterior, principal, perfil, HPR1, sidecar
  y slot modificado. Se recifra la capa exterior de los negativos internos
  para comprobar la capa concreta, no solamente el primer tag.
- Ausencia de credenciales, contraseña/HWID incorrectos, esquemas/schedules
  no habilitados, archivo truncado y límites de tamaño/Argon2.
- Continuación SHA-256 frente a hashlib en los límites de padding.
- Ambos lanzadores desde un directorio distinto, `.HC`, credenciales stdin,
  ruta del bot y proceso Cloud con los códigos públicos habituales.

Las pruebas anteriores de HC/HCCFG y SocksIP siguen pasando. La matriz C0
canónica no se modifica. `_hc_hccfg.py` permanece idéntico al de la rama
base del cambio. CI C2 incluye la nueva suite explícitamente.

## Icono y paquete

El WebP de 192×192 se extrajo del recurso original del APK y su SHA-256
coincide con el manifiesto. El PNG tiene exactamente los mismos píxeles
RGBA; se conserva también el WebP sin modificar. Ningún umbral de peso
excluye el icono.

El ZIP de código incluye la carpeta de la app y las dos dependencias
históricas Python en su ubicación relativa. Se verifica extraído fuera del
repositorio. No contiene APK, librerías nativas, muestras `.hc`, respuestas
descifradas privadas, copias de seguridad ni registros de la investigación.
Extraído en un directorio temporal independiente, su CLI devolvió doce
resultados completos idénticos: cuatro modos de bloqueo sintéticos, dos
formatos históricos y las seis exportaciones reales, incluidas las cuatro
protegidas con sus credenciales originales.

No hay script de catálogo. No se ha compilado Android ni desplegado o
fusionado el PR. No se certifican un escritor de archivos, importación en
Android, otros builds ni combinaciones de esquema/schedule no verificadas.
