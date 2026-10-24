# Validación y límites

2026-10-24: comparación JSON **completa**, sin guardar datos privados en Git.

| Fuente | Versión | Registros | Campos protegidos, incluidos vacíos | JDK/worker |
|---|---:|---:|---:|---|
| Asset principal real | 36 | 75 | 808 (620 no vacíos) | Iguales |
| Respuesta remota real | 35 | 74 | 797 (609 no vacíos) | Iguales |
| Asset secundario real | 9 | 32 | 0, interior en claro | Iguales |

Se contrastaron envolturas, todos los campos conocidos, listas y metadatos.
Oracle independiente JDK `tests/golden/speicers_oracle.java`; biblioteca AES
distinta de PyCryptodome y rotación mediante Character sobre char Java.
`speicers_verify.py` compara el documento completo con el JDK y el bridge,
imprimiendo únicamente versión, conteos y paridad. Las respuestas de servidores
se guardan de forma privada para verificar; no forman parte de los fixtures.

```bash
python -m unittest tests.test_speicers_pro tests.test_http_fenixvpn tests.test_cloud_c8_vpn_registry -v
cd cloud/web
node --test tests/speicers-private.test.mjs tests/server-vpn-catalog.test.mjs tests/server-vpn-provider.test.mjs tests/server-vpn-version-sync.test.mjs
```

14 pruebas nuevas de Python y 15 regresiones existentes: **29 aprobadas**.
Incluyen worker aislado real, resultados íntegros, filas deshabilitadas,
booleanos, datos desconocidos, límites, JSON duplicado/no finito/profundidad,
campos protegidos inválidos, glifos/UTF-8/encabezados, redirecciones, CLI
independiente con permiso 0600 y rechazo de sobrescritura. Dos catálogos
sintéticos adicionales coinciden con JDK, incluido un campo con letras Unicode
BMP/suplementarias y emoji. Los dos formatos `.sks` reutilizan los vectores
GCM y DES generados por JDK de Fenix: XML, duplicados, vacíos y flags íntegros.

**52 pruebas Node aprobadas.** El test nuevo verifica ausencia de Speicers en
la respuesta pública incluso con habilitación global y disponibilidad forzada,
ausencia en broker e icono y conservación de versión 40 / 40 fichas. Las suites
de proveedores, catálogo y sincronización conservan sus resultados.

La CLI autónoma copiada fuera del repositorio descargó y guardó de nuevo el
catálogo remoto 35/74. No se ejecutó en Termux/Android: la compatibilidad se basa
en Python estándar + PyCryptodome, sin APIs de escritorio, ADB o privilegios.

El primer intento con el Python global falló en el worker por dependencias
instaladas solo en el HOME del host. Se repitió con venv y dependencias reales;
el worker cambia HOME deliberadamente. No se cambió código productivo por ese
problema de entorno. Dependencias adicionales de regresión: msgpack y argon2-cffi.

Pendiente: exportación `.sks` real y prueba de la interfaz Android. No se afirma
despliegue, importación en un teléfono ni autenticidad por MAC para catálogos
CBC. El ocultamiento es de la lista/broker públicos; el código permanece en la
rama del repositorio por instrucción del usuario, no es un almacén secreto.
