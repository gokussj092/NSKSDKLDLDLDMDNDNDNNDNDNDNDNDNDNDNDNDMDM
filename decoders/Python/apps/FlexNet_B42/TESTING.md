# Validación dirigida — FlexNet B46

## Continuación del 24 de octubre: concesiones online

**28 pruebas Python y tres pruebas Node aprobadas**, incluidas las 22 anteriores:

```bash
PYTHONPATH=cloud/workers/python:. python -m unittest tests.test_flexnet_b46_grant tests.test_flexnet_b46 tests.test_flexnet_b42 -v
node --test tests/flexnet_b46_capture.test.mjs
```

`FlexB46VectorGenerator.java` añade una concesión/reto sintéticos para el mismo
perfil online del golden anterior. Se compara todo el XML, propiedades reales,
ambos CLI y el colector local con permisos 0600 y sin sobrescritura. Rechaza
bindings alterados, otra muestra, clave incorrecta (GCM), Base64 no canónico,
JSON duplicado, mezcla de opciones y capturas para otras modalidades.

`scripts/apk_analysis/flexnet_b46_grant_oracle.py` ejecuta el parser de cabecera
y bloque de binding originales, con SHA-256 exacto del SO B46. **87 casos**:
vector válido, 85 alteraciones rechazadas y clave alterada que llega a GCM y
falla. La comparación de bytes también ejecuta el código original. No emula
RSA/JNI/Android ni acredita una importación completa. Las tres pruebas Node
son mocks del flujo y del borrado del array; no una prueba Frida en teléfono.

Las muestras reales de 1388 y 1826 bytes aún devuelven `ONLINE_AUTH_REQUIRED`.
El usuario confirmó que se importan en la app oficial. Falta capturar sus
concesiones en ese dispositivo. Ver
[análisis y pasos](../../../../docs/FLEXNET_V2_4_AUTHORIZED_IMPORT.md).

## Validación previa del 22 de octubre

2026-10-22. **22 pruebas FlexNet aprobadas** (cinco nuevas y 17 de B42), sin
suites completas del proyecto. Comando desde la raíz:

```bash
PYTHONPATH=cloud/workers/python:. python -m unittest tests.test_flexnet_b46 tests.test_flexnet_b42 -v
```

Los vectores de `tests/golden/FlexB46VectorGenerator.java` se producen mediante
OpenJDK/JCE, independientemente del lector Python. Cubren v5 interior B46,
online con clave sintética, v6 con clave de setup sintética y FLXFLD protegido.
Todo el XML original coincide; se verifican siete propiedades, campos reales
frente a aliases, metadatos desconocidos, worker aislado, ambos CLI fuera del
repo, ausencia/error de claves, binding y etiquetas alteradas sin fallback.
También pasan formatos v1/v2/v3/v4 (incluida cabecera opcional v4), fixtures
B42 offline/online y catálogos FBS1/RSA. Se conservan los 30 materiales legacy.

Confirmación adicional puntual: la función original ARM64 de B46 en
`libvpnbridge.so + 0x335474` abre el campo SNI sintético y devuelve exactamente
`real.example.invalid`, igual que JDK/Python. Ejecución aislada con libc emulada,
sin Android, suplantación del dispositivo o llamadas al servidor.

**Muestra real:** 1388 bytes, SHA-256
`853621417da94b6d5effa5db47ad481d193ec37c7a960d1a5f25dbc6ffbb1b76`.
Inspección: v5, modo 2, suite 1, mínimo 46, cabecera 45 y payload 1343 bytes.
Antes devolvía `MINIMUM_BUILD`; ahora identifica `ONLINE_AUTH_REQUIRED`.
No se aportó la clave online, por lo que no se recuperó su XML/JSON ni se
certifica el resultado real. La inspección no acredita autenticidad GCM.

No se incluyen APK, bibliotecas nativas, muestra privada ni claves reales en Git.
`git diff --check` correcto. Sin despliegue, release Android ni publicación de
novedades. Los catálogos actuales del APK B46 no forman parte de esta validación.
