# Validación dirigida — FlexNet B46

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
