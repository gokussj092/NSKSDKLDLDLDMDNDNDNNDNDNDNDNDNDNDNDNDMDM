# Auditoría de importación HTTP Custom — 2026-10-26

## Conclusión y alcance

Se corrigieron errores reproducibles del laboratorio y se generaron cinco
variantes auditadas. **No se confirmó todavía la causa del rechazo JSON en
Android. Ninguna nueva variante está certificada como importable.**

Base auditada: rama `feat/temporary-original-app-config-export-lab`, commit
`b21d3dbc3bd9f775a62a299d1c33054a7cbf2795`. No se modificaron componentes de
producción. Las pruebas de restricciones se limitan a la edición autorizada
por el propietario; no cambian contraseña, HWID, expiración o validación remota.

## Evidencia real

- Fuente: `3 long grok.hc`, 4230 bytes,
  SHA-256 `167593e228e10c3eaa98333198f0c1c946f328b7b99ab2ef574bc429576ca4ba`.
- Rechazado histórico: 4207 bytes,
  SHA-256 `78d257386e9a50cc4548f44df0d67cdb37526941952ebcf490a66f6d74ee6f6f`.
- Ambos salieron del ZIP privado; la fuente adjunta coincide con la del ZIP.
  No falta ninguna muestra necesaria para la matriz HTTP Custom.
- APK suministrado: paquete `xyz.easypro.httpcustom`, versión
  `7.11.28 - Patch 1`, versionCode `899`. `base.apk` SHA-256
  `e990a9376b36974d4fec864e9dc8ebca69578e78e31bc94f7d3c07ced71d39e8`.
- Una capa carrier UTF-8/Latin1; HCX4 exterior, HCCFG10/n11; un perfil HPR1/HPC1
  con sidecar. Cinco tags por archivo: outer, main, sección de perfil, HPR1 y
  sidecar. PyCryptodome y `_xdec_pure` los verifican, sin stream fallback.
- El rechazo Android histórico es **informado por el usuario**. No se obtuvo
  una traza de excepción del importador original.

## Hallazgos confirmados y correcciones

| Hallazgo | Comprobación | Corrección / implicación |
| --- | --- | --- |
| Scripts no ejecutables con el comando documentado | `python .../hc_hcx4_n11_experiment.py --help` falla por import de `decoders`; la matriz usa el mismo import incorrecto | Bootstrap por ruta absoluta, probado desde un cwd ajeno |
| Baseline no preservaba serialización exacta | Principal original 426 bytes; `json.dumps` compacto produce 419 por siete escapes `\/` | Baseline byte-idéntico; ediciones por tokens, sin normalizar otros valores |
| Igualdad Python permite confundir booleanos y números | `False == 0` y `True == 1` podían ocultar cambios no autorizados | Igualdad/diff recursiva con tipos exactos |
| Staging sobrescribía muestras; matriz podía escribir parcialmente antes de detectar colisiones | Redirecciones `>` y detección tardía de salidas ya existentes | Hashes primero, directorio nuevo, apertura exclusiva 0600 |
| Rechazado histórico tiene JSON sintácticamente válido | JSON estricto y cinco etiquetas auténticas en dos backends | El texto de la app no demuestra un fallo sintáctico o criptográfico |
| No falta `main` en la proyección usada para esta muestra | Comparación con JSON principal original, tipos exactos: coincide íntegro | La pérdida por normalización de `main` no se observa en este caso |
| El sobre histórico cambió solamente `i.b/i.c` | `j`, sidecar, perfil y resto del sobre coinciden | No hay evidencia de omisión de esos campos en el intento rechazado |
| El tipo de acceso cambió de string a booleano | Fuente `lock_all`; rechazado `false` | Se bloquea por defecto y se permite explícitamente en D/E como prueba; aún no prueba causalidad |
| Fixtures legibles estaban en repositorio público | API de GitHub indica visibilidad pública; inspección local de JSON | Retirada del árbol actual e ignore ampliado; historial previo permanece |

La vista `protections` es derivada y no se cifra como sección nueva. El
script abre el sobre original y reemplaza solo `i.b/i.c`. Los nombres legibles,
`options` procesadas y otros campos de presentación nunca se usan para
reconstruir HPC1: `j` se conserva íntegramente, cifrado incluido. Eso evita
perder opciones, campos vacíos, flags, fecha, HPR1 y sidecars aunque otro lector
histórico aplane o suprima campos en su salida.

## Análisis del importador

Se examinó el APK adjunto con Androguard 4.1.4 y JADX 1.5.6. Las clases
`dev.epro.r0.U9085043933007906326` (contenedor) y
`dev.epro.r0.N1319217069659000081` (configuración/derivación) exponen sus métodos
relevantes como `native` y registran implementaciones en `libf2c.so`.
La decompilación Java por sí sola no entrega la validación del JSON.

Una exploración local acotada de inicializadores ARM64 recuperó estructuras
auxiliares, pero no un parser ejecutable ni un enum de acceso verificable.
**No equivale a ejecutar el importador** y no se usa como evidencia de
aceptación/rechazo. No se ejecutó JNI_OnLoad ni se obtuvo una sesión Android.

Por tanto, no se puede afirmar que `false` cause una excepción de tipos, ni que
`"false"`, `"unlocked"` o cualquier otro string sea un valor legítimo. Ninguno
se añadió como supuesta corrección. `https://spdecode.xyz` es el valor autorizado
de prueba, no un endpoint de actualización de formato demostrado.

## Resultado local A–E

| Caso | Cambio respecto al original | AEAD / JSON sintáctico | Tipos del original | App original |
| --- | --- | --- | --- | --- |
| A | Ninguno; principal de 426 bytes idéntico | 5/5 tags, válido | Conservados | Pendiente |
| B | Solo `main.g.v`, nota exacta solicitada | 5/5 tags, válido | Conservados | Pendiente |
| C | Solo `main.u`, URL solicitada | 5/5 tags, válido | Conservados | Pendiente |
| D | Solo `main.g.a = false` | 5/5 tags, válido | Cambio string → bool, diagnóstico | Pendiente |
| E | Los tres cambios | 5/5 tags, válido | Cambio string → bool, diagnóstico | Pendiente |

Hashes y tamaños de ESTA generación: `results/import_matrix_2026-10-26.json`.
Verificación independiente: `results/audit_2026-10-26.json`. Se verifican bytes
no editados, perfil cifrado, todo metadato del sobre y profundidad carrier.
Las longitudes UTF-8 cambian con los nonces; no comparar tamaños como prueba de
pérdida de datos. Mantener tanto esta matriz como sus `.hc` privados asociados.

## Pruebas automatizadas y entorno

- 11 pruebas nuevas, todas correctas: CLI, baseline exacto y carriers 0/1/2,
  campos desconocidos, escapes/Unicode/exponentes, ediciones permitidas,
  tipos bool/int, claves duplicadas, NaN/Infinity, rutas ausentes/solapadas,
  escrituras exclusivas/symlinks y rechazo de manipulación en cada capa AEAD.
- 9 pruebas existentes de `tests.test_http_custom_899`, todas correctas,
  incluidas entrada CLI/bot y cuatro modos del worker con datos sintéticos.
- Python 3.12.14; entorno aislado con PyCryptodome 3.23.0 y argon2-cffi 25.1.0
  según los requisitos canónicos del codec. Se comprobó además la matriz con
  otro backend de descifrado puro Python.
- La primera ejecución del test del worker falló por dependencias instaladas
  solo en el user site del entorno anfitrión; el subprocess cambia su entorno
  y no las veía. Al instalar los requisitos en un venv pasó 9/9. No se cambió
  el worker ni el producto para corregir una condición de la máquina de prueba.
- Staging real y reintento de staging/matriz existentes comprobados: se rechaza
  sobrescribir y el hash de la fuente permanece intacto.

## Prueba manual necesaria en Android

1. Respaldar las configuraciones locales. Usar HTTP Custom build 899 y una
   configuración propia/autorizada. No compartir capturas con conexiones.
2. Importar el control original y comprobar que el punto de partida es válido
   en esa instalación. Hacer primero la prueba de importación sin conectarse;
   aislarla de actualización remota o conexión VPN.
3. Importar **A_baseline_rewrap.hc**. Si falla, detener el diagnóstico de campos:
   todavía hay una diferencia de carrier/contenedor/serialización u otra
   validación del importador que investigar. Registrar el mensaje literal.
4. Si A entra, importar B y C por separado. Confirmar nota y URL sin dar por
   aprobada una conexión/actualización remota. Puede existir política posterior.
5. Importar D y E para aislar el cambio booleano. Si A/B/C entran y D/E fallan,
   el rechazo queda aislado al campo/valor/tipo de acceso, sin probar por sí
   solo cuál enum desbloqueado acepta el proveedor.
6. Para proponer un valor textual nuevo, obtener una exportación legítima
   creada como desbloqueada desde la misma app y comparar su esquema.
7. Registrar build, SHA-256 exacto, reconocimiento, aceptación del JSON,
   mensaje literal, aplicación de la nota/URL y cualquier efecto posterior.
   Conexión y actualización remota se validan aparte con autorización.

El ZIP nuevo incluye una plantilla de resultados manuales. No escribir
`PASS` en compatibilidad del proveedor a partir del roundtrip local. Expiración,
contraseña, HWID y servidores no se modifican. Los otros exportadores quedan
fuera del alcance hasta cerrar esta investigación.
