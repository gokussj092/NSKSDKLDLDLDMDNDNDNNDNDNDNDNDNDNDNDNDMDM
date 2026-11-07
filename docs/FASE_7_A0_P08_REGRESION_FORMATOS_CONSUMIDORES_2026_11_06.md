# F7-A0-P08 — Regresión de formatos y consumidores originales

**Rama:** `feat/nuevas-integraciones` · **Estado:** IMPLEMENTADO / CI PENDIENTE EN EL HEAD DE P08; **sin ejecución APK de terceros ni despliegue de producción**.

## Objetivo y decisión del propietario

Regresar a ejecutar pruebas que invocan **el código actual de métodos, worker y rutas Cloud originales** sin modificar esos métodos, sus pruebas históricas, fixtures existentes ni los 63 scripts de análisis. Los resultados deben diferenciar una regresión **realmente ejecutada sobre código de producción** de una **verificación real con APK/servidor VPN de tercero**. La segunda **no** se certifica en P08.

La protección de GitHub Branch Protection fue expresamente **descartada por ahora** por el propietario. GitHub Actions sigue siendo el medio de validación de CI y las fusiones permanecen bajo revisión manual. P08 no activa reglas, no hace merge y no despliega. P07 conserva el auditor de wiring y el registro de controles; la protección efectiva queda opcional, no bloquea este avance.

## Implementación

- `analysis/platform/apk-tooling/p08_regression_matrix.v1.json`: **19 suites existentes**, sin reescribirlas: 12 Python (archivo/texto, formatos actuales, catálogos CATNET/NAMO/HTTP Conexión, renovación, HA export *unlocked*, worker y transporte) y 7 Node.js (catálogo en rutas HTTP, versiones, snapshots/chunks/hash/reanudación, integración proveedor, watch y política de exportación).
- `scripts/ci/run_a0_p08_regression.py`: selecciona suites por nombre fijo y realiza ejecución real con `unittest` o `node --test` usando los tests **ya existentes**. Exige mínimos por suite y formato/consumidor inmutables en el validador; bloquea módulos ausentes, tests omitidos, fallo de procesos o reducción del número de casos. Compara SHA-256 antes/después de los scripts originales, decodificadores, worker, librerías y rutas Cloud sin sobrescribir archivos.
- `tests/test_a0_p08_regression.py`: pruebas unitarias negativas de matrices alteradas, omisión de test, simulación de éxito, reducción de cobertura, fallo de test, `skipped`, modificación de fuentes y falsos reclamos VERIFIED_REAL.
- `.github/workflows/f7-a0-method-evidence.yml`: añade verificación read-only de la matriz P08 y sus pruebas de integridad, sin ejecutar métodos en ese job.
- `.github/workflows/f7-a0-p08-regression.yml`: dos jobs independientes sobre PR: Python 3.11/Node 22/Java 17/PHP y dependencias del proyecto para ejecutar 12 suites Python; y Node 22 con dependencias existentes de `cloud/web` para ejecutar 7 suites Node. Reportes JSON sanitizados, sin stdout bruto, secretos, llaves, APK o resultados sensibles; sin aplicar branch protection.

El archivo `p08_regression_matrix.v1.json` declara expresamente `real_vendor_apk_verified=false`, `real_vendor_endpoint_verified=false`, `real_android_e2e_verified=false`, `approval=NONE_GRANTED`. Los tests están concebidos para fixtures locales/sanitizados y oráculos independientes parciales; instalar dependencias en CI sí puede requerir red, **eso no convierte las pruebas VPN en pruebas contra redes externas**.

## Cobertura por formato y consumidor

| Categoría | Código bajo prueba | Referencias existentes | Limitación |
| --- | --- | --- | --- |
| Archivos, HC, TLS y eV2Ray | Módulos Python actuales, worker Cloud y puente de archivos | 60 vectores sintéticos C2, A23, generadores de formato | No APK de tercero ni Android real |
| Texto | `cloud/workers/python/text_bridge.py` | Vectores sintéticos y entradas inválidas | No enlace/proveedor externo |
| Catálogos | CATNET, HTTP Conexión, NAMO, KSH/MKK/DTunnel y capa Node Cloud | Oráculos Java/Node existentes, comparación con worker y respuestas falsas | No descargar endpoints reales |
| Renovación | Firebase/HTTP Conexión | Emulaciones temporales y fallos controlados | No tokens reales ni Google Play |
| Exportación | `exports/hat.py`, política `compatible-export-policy.mjs` | Fixtures de preservación de bytes/campos y rechazos | No instalación Android real |
| Transporte | `server.py`, rutas Cloud, hashes/chunks/snapshots | Cliente sintético, HTTP interno, recuperación y corrupción | No VPN ni transferencia Android→Cloud |

**Interpretación honesta:** `PASS` significará que los métodos y sus consumidores pasaron esas pruebas **realmente ejecutadas** sobre datos sintéticos o públicos sanitizados, y los scripts de producción no fueron modificados durante su ejecución. No significa que 19 aplicaciones se hayan conectado a sus servidores reales, que todas las versiones funcionen, ni que el servicio Android de análisis de APK esté operativo.

## Comprobaciones manuales

```bash
# Valida solo matriz/integridad; no ejecuta descifrado.
python -m unittest discover -s tests -p 'test_a0_p08_regression.py' -v
python scripts/ci/run_a0_p08_regression.py --check-only --output /tmp/p08-inventory.json

# En un entorno con requisitos del proyecto instalados:
python scripts/ci/run_a0_p08_regression.py --runtime python --output /tmp/p08-python.json

# En entorno con Node 22 y dependencias cloud/web instaladas:
python scripts/ci/run_a0_p08_regression.py --runtime node --output /tmp/p08-node.json
```

Consultar [F7-A0 P08 Independent Regression](https://github.com/gokussj092/NSKSDKLDLDMDNDNNDNNDNDNDNDNDNDNDNDNDMDM/actions/workflows/f7-a0-p08-regression.yml) y la [suite A0](https://github.com/gokussj092/NSKSDKLDLDMDNDNNDNNDNDNDNDNDNDNDNDMDM/actions/workflows/f7-a0-method-evidence.yml). **Registrar SHA y run exitoso** antes de dar P08 por validada.

## Pendientes de aceptación y trazabilidad

1. Confirmar CI independiente P08 **ambos jobs**, casos ejecutados, origen de los datos y reportes; distinguir falsos positivos/errores de entorno de regresiones reales.
2. Aumentar cobertura automatizada de rutas dinámicas y consumidores no mapeados por el grafo P06, sin dar el sistema por completo.
3. Obtener corpus autorizado de APK VPN reales, APKS bundletool, ELF ARM64, renovaciones legítimas cuando aplique; ejecutar en VM aislada con recursos persistentes, evidencias y permisos P01/P03/P05.
4. Integrar extremo a extremo Android → Cloud → resultado cifrado con autenticación, cuotas, cancelación y soporte A4/A5/A9 antes de declarar disponible el análisis automático.
5. La aceptación global F7-A0-P09 sigue pendiente hasta cerrar o registrar formalmente riesgos residuales de P01–P08.

**No marcar F7-A0, P08 ni la automatización de APK DONE solo porque el pipeline CI se muestre verde.**

## Primeras ejecuciones y diagnóstico independiente

- [F7-A0 Method Evidence — PR 42339902423](https://github.com/gokussj092/NSKSDKLDLDLDMDNDNNDNNDNDNDNDNDNDNDNDMDM/actions/runs/42339902423) **SUCCESS** sobre `c72299fa`: matriz, tests P08, política P06 y anteriores aprobadas.
- [P08 independiente — run 42339902478](https://github.com/gokussj092/NSKSDKLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42339902478) **FAILURE parcial** en primer intento: job Node **SUCCESS, 7/7 módulos y 69/69 tests**; job Python **11/12 módulos PASS**, registró 78 casos ejecutados y falló `server-vpn-transport` al ejecutarse solo, 1 caso `_FailedTest`.
- **Causa identificada sin cambiar código funcional:** `cloud/workers/python/server.py` utiliza el import `from engine import ...`; su runtime normal añade `cloud/workers/python` al path de módulos. El nuevo runner independiente arrancaba los tests desde la raíz y no reproducía ese contexto. La suite de validación general sí ejecuta correctamente sus **2 casos** ([Validate 42335982835](https://github.com/gokussj092/NSKSDKLDLDMDNDNNDNNDNDNDNDNDNDNDNDMDM/actions/runs/42335982835), SUCCESS) gracias a su entorno y orden de importaciones. Se cambió **solo el PYTHONPATH del runner P08** para reproducir el entorno del worker, y se agregó test de contrato que verifica este entorno; no se tocó `server.py` ni `test_cloud_server_vpn_transport.py`.
- El comparador SHA-256 informó **486 archivos operativos intactos** antes y después de la ejecución Python y Node. Los 63 scripts originales siguen sin cambios.

**Pendiente para certificar ejecución completa:** obtener SUCCESS en ambas ramas del workflow con el último commit que incluye el ajuste al `PYTHONPATH`; no declarar el primer run fallido como verde, ni P08 completada mientras no termine CI. El primer fracaso corresponde a aislamiento de ejecución de tests, no prueba de error del descifrado en producción.
