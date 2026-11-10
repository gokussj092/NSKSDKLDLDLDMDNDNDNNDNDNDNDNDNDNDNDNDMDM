# HTTP Custom — archivos .hc

**Investigación 2026-11-01:** las dos muestras nuevas HCCFG 11/n13 con Extra
Protection autentican HCX4, pero **0/2 están descifradas**. El motor sigue
habilitado para HCCFG 10/n11/n12 y sus rutas históricas. No se anuncia soporte
de la versión nueva hasta verificar su JSON interior completo.
[Evidencia y siguiente requisito](../../../../docs/cloud/HTTP_CUSTOM_11_N13_REINVESTIGACION_2026_11_01.md).

![HTTP Custom](HTTP_Custom.png)

APK analizado: **HTTP Custom 7.11.28 - Patch 1**, `xyz.easypro.httpcustom`,
versionCode **899**. Este módulo añade **HCX4 / HCCFG 10, n11 y n12** al
lector de archivos. El codec no hace peticiones de red. La importación online
se integra aparte en el broker API y reutiliza este mismo motor; ver
[HTTP_CUSTOM_ONLINE.md](../../../../docs/cloud/HTTP_CUSTOM_ONLINE.md).

## Uso

Desde la raíz del repositorio, con Python 3.10 o posterior:

```sh
python -m pip install -r decoders/Python/apps/HTTP_Custom/requirements.txt
python decoders/Python/apps/HTTP_Custom/HTTP_Custom.py archivo.hc
python decoders/Python/apps/HTTP_Custom/file_decoder.py archivo.HC > resultado.json
python decoders/Python/apps/HTTP_Custom/file_decoder.py archivo.hc --ask-password
python decoders/Python/apps/HTTP_Custom/file_decoder.py archivo.hc --hwid TU_HWID_ORIGINAL_DE_32_CARACTERES
python decoders/Python/apps/HTTP_Custom/file_decoder.py archivo.hc --ask-password --hwid TU_HWID_ORIGINAL_DE_32_CARACTERES
```

También se admite `--password-file clave.txt` o `--auth-stdin`, que recibe un
objeto JSON con los campos opcionales `password` y `hwid`. La contraseña no
se recorta; el archivo de contraseña admite un salto de línea final. El HWID
se normaliza como en el motor anterior. No se adivinan contraseñas ni HWID.

El ZIP de código conserva la misma estructura `decoders/Python/`; hay que
extraerlo completo. **No hace falta proporcionar el APK**, instalar Android,
ejecutar bibliotecas nativas ni conectarse a un servidor para descifrar.

API de Python:

```python
from decoders.Python.apps.HTTP_Custom.file_decoder import run

with open("archivo.hc", "rb") as stream:
    texto = run(stream.read(), password=None, hwid=None)
print(texto)
```

`run(data: bytes) -> str` es no interactivo. Los archivos modernos producen
JSON. Para formatos históricos se conserva la salida y el comportamiento de
los motores originales.

## Formato nuevo comprobado

1. El archivo puede ser binario o UTF-8 de caracteres Latin1, incluso aplicado
   varias veces. Se lee como bytes, sin transformar CR/LF.
2. HCX4 contiene un nonce de 24 bytes y ciphertext con tag Poly1305 de 16
   bytes. Su AAD es `HCX4|xyz.easypro.httpcustom|1`.
3. La derivación nativa continúa dos estados SHA-256 precomputados de HMAC
   sobre `E9 || SHA256(certificado DER) || datos`. Los estados se recuperaron
   de `libruntime.so`; `crypto.py` los reproduce en Python. No equivale a
   aplicar SHA-256 normal a esos bytes.
4. El resultado alimenta HKDF-SHA256 con las etiquetas
   `hc-envelope-seal-{salt,info}-v4`. XChaCha20-Poly1305 abre el JSON HCCFG.
5. HCCFG **10 / s1 / h1** usa n11, o n12 con HWID y slots de clave. El
   transcript incorpora paquete, versión de formato, features, build, HWID
   cuando corresponde y semilla. La contraseña, si existe, aporta Argon2id13
   antes de HKDF. Cada sección tiene su propia AAD.
6. Se autentican las secciones principal y de perfiles, la capa HPR1 y el
   sidecar opcional. HPC1 guarda once campos, incluidos opciones, flags y
   fecha. Una etiqueta inválida interrumpe el descifrado; esta ruta no usa
   fallback de flujo sin autenticación.

La correspondencia n11/n12 → familia nativa 4 se contrastó en
`N1319217069659000081.c/d`; el contenedor exterior está en
`U9085043933007906326`. La derivación HMAC/HKDF se contrastó además con
cuatro vectores públicos obtenidos ejecutando las funciones nativas
`0x1d63f0` y `0x1e6ab0` con contexto de certificado modelado y datos
sintéticos. El criterio decisivo fue la autenticación de archivos reales,
no la mera presencia de cadenas en el APK.

## Datos conservados

- `config`: perfiles completos, con `options` anidado y su `options_text`
  original; se conservan campos vacíos, tipos JSON, flags, fecha y etiqueta.
- `main`: objeto principal completo, incluidas sus opciones desconocidas.
- `protections`: nombres legibles; sus claves originales siguen en `main`.
- `other_sections`: contenido de secciones adicionales; el binario se
  representa en Base64. Los sidecars de perfiles conservan texto o bytes hex.

La salida pública del lector no incluye el envelope ni una clave `format`;
conserva las cinco claves verificadas por los tests. La apertura del envelope
se usa internamente para autenticar y seleccionar el motor.

No se aplanan opciones que puedan sobrescribir host, puerto u otros campos.
El bloqueo visual de payload se conserva en los metadatos; no impide leer
los campos que están presentes en las muestras descifradas. No se inventan
datos omitidos por un exportador.

## Compatibilidad y límites

| Ruta | Estado |
| --- | --- |
| HCX4, HCCFG 10, n11 sin credenciales | Dos exportaciones reales completas y autenticadas |
| n11 con contraseña | Dos exportaciones reales completas y autenticadas con su contraseña original |
| n12 con HWID | Dos exportaciones reales completas y autenticadas con su HWID original, incluidos sus slots de clave |
| Contraseña y HWID simultáneos | Vectores sintéticos contrastados con la KDF nativa; casos correctos e incorrectos probados; sin muestra real de doble bloqueo |
| ChaCha20, RST/AES, JKL y demás rutas del lector histórico | Delegación a `HTTPCUSTOM.py`, sin sustituir sus algoritmos |
| HCCFG 1/2/5/7, n1/n2/n7/n8 | Delegación a `_hc_hccfg.py`, sin modificar ese motor |
| Otras combinaciones de esquema/schedule, incluidos n13/n14 | No habilitadas por este módulo; no hay una muestra validada que certifique su formato completo |

Los números de versión del APK y los de esquema son distintos. Las cadenas
HCX1–4, n1–14 y otras versiones de HCCFG presentes en el binario no implican
soporte de todas sus combinaciones. La compatibilidad confirmada aquí se
limita a lo indicado en la tabla; no se certifican otros builds.

Las seis exportaciones reales de build 899 se abrieron completas: doce
perfiles HPC1, sus capas HPR1, los JSON principales y todos los metadatos.
Los resultados coinciden entre la apertura de referencia, la API Python,
ambos lanzadores y el worker Cloud, sin resultados parciales. Las
credenciales originales se usaron solo para la verificación local y no se
incluyen en el repositorio ni en el paquete descargable.

Límites del lector nuevo: archivo de hasta 16 MiB; Argon2id con 1–10
iteraciones y 8 KiB–256 MiB de memoria; hasta 4096 slots HWID. Cloud mantiene
sus propios límites de tiempo y salida (4 MiB). El script independiente
puede usarse cuando el JSON completo supera ese presupuesto de Cloud.

Errores relevantes: `PASSWORD_REQUIRED`, `HWID_REQUIRED`,
`HWID_PASSWORD_REQUIRED`, `AUTH_FAILED`, `UNSUPPORTED_SCHEMA`,
`UNSUPPORTED_SCHEDULE` y `ARGON2_LIMIT`. No se imprimen perfiles parciales
cuando falla una capa autenticada.

## Integración y archivos

Carpeta: `decoders/Python/apps/HTTP_Custom/`. Rama:
`feat/austroplus-vpn-13-0-1-decoders`; [PR #96](https://github.com/Gh0stDeveloper/SP-DECODE/pull/96).
Se sigue `docs/cloud/SERVER_VPN_NEXT_CHAT_GUIDE.md` para la organización.

La extensión `.hc` conserva su registro canónico en `decoders.json` y la
matriz C0. `HTTPCUSTOM.run` añade la detección HCX4 antes de las rutas
anteriores; `cloud/workers/python/hc_bridge.py` recibe contraseña/HWID por
stdin y devuelve sus códigos públicos habituales. No se añade una ruta de
catálogo, una ficha Server VPN ni un motor dentro de Android.

`HTTP_Custom.webp` es el recurso original exacto del APK; `HTTP_Custom.png`
es una conversión sin pérdida de sus píxeles RGBA para facilitar su uso.
Origen, dimensiones y checksums están en `manifest.json`. Se incluyen ambos.

`TESTING.md` distingue muestras reales, vectores nativos y pruebas sintéticas.
No se incluye APK, `.hc` privado, configuración recuperada ni credencial
real. Este paquete es un lector; no implementa un exportador editable ni
certifica un roundtrip de importación en un dispositivo Android.

Revisión de paridad Offline 2026-11-09: expediente y comprobación privada sin
datos de usuario en `analysis/_intake/httpcustom-offline-20261109/`. Corrige
UTF-8 y clasificación Unicode en el lector histórico C++; no modifica este
codec Python. El build exportador no se deduce del formato `verCfg:57`.

Expediente del consumidor Offline build 42: `analysis/com.ghostdeveloper.spdecode.offline/42/`.

### Revisión original 4.10.16 / registros 57

`analysis/xyz.easypro.httpcustom/564/` conserva el inventario del APKM del
propietario, primitivas JNI originales y la comparación del archivo privado.
El APK marca 564; el archivo declara verApp 565. El lector de revisión 57
conserva los 32 campos y metadatos y recupera el JSON V2Ray antes omitido.
Un valor histórico de Psiphon aún no interpretado se conserva con aviso de
resultado parcial; no se presenta como descifrado. Servidor y Offline C++
coinciden; las representaciones se eligen por versión observada, sin decidir
por texto que simplemente parezca legible. No certifica todo exportador.
