# Pruebas de CREEB INJECTOR 38.0

Comprobaciones enfocadas del 2026-10-23:

- **10 aprobadas**: nueve del lector y una del registro C8/C0. Tres documentos
  DES/XML JDK (normal, contraseña/HWID, duplicados/Unicode) y dos bundles JSON
  con varios perfiles, con y sin restricciones. JSON entero, Properties,
  entradas y XML sin recortes; valores vacíos, hashes, flags y desconocidos.
- **10 regresiones AboWaged aprobadas** al añadir la nueva ruta en el mismo
  motor. `.crev` conserva su script histórico. C8 efectivo 250 / C0 240.
- `creeb_verify.py --worker`: **cinco documentos completos iguales**, tres
  DES/Properties con JDK y cinco resultados de worker íntegros. Cero muestras
  reales aportadas. Sin necesidad de contraseña/HWID externos.
- CLI por ruta y stdin desde otra carpeta; handler HTTP del worker real para
  ambas variantes. Errores sanitizados de JSON, DES incompleto, UTF-8, esquema,
  límites, entidades, DTD personalizados y surrogate aislado.
- Catálogo: fuente `UpdateAsync` inspeccionada como actualización de APK;
  **no** se registra ni certifica un catálogo remoto de servidores.

```bash
java -XX:-UsePerfData tests/golden/creeb_oracle.java --generate > /tmp/creeb_vectors.json
python -m unittest tests.test_creeb_injector tests.test_cloud_c8_vpn_registry -v
python -m unittest tests.test_abowaged_vpn -v
python scripts/apk_analysis/creeb_verify.py --worker
# Cuando se aporte una exportación real:
python scripts/apk_analysis/creeb_verify.py --worker /ruta/ejemplo.creeb
```

El oracle genera únicamente datos ficticios. Para actualizar el fixture,
formatear su salida JSON en `tests/golden/creeb_vectors.json`; no incorporar
archivos de usuarios ni catálogos reales. Runtime/tests: PyCryptodome. La
regeneración y paridad independiente requieren JDK 17+; las pruebas habituales
leen los vectores guardados y no necesitan Java, APK ni red.

La prueba Dalvik de la clase anónima conserva 64 instrucciones en una salida
privada mediante `dex_method.py`. Revisar ANALYSIS.md y los hashes antes de
atribuir esa receta a otra versión. No se ejecutó la suite completa, no hay
prueba de VPS desplegada ni importación Android de un archivo real.
