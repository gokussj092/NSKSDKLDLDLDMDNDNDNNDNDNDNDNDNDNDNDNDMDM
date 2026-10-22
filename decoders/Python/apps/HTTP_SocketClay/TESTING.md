# Validación de HTTP SocketClay 3.4.0

Fecha: 2026-10-21. APK base SHA-256
`542430bbe7313d0d1992611df0b3bbec68c83ad412bb9771f0422aece1a082e6`.

## Evidencia independiente

- Manifest binario: `com.socketclay.http`, 3.4.0, 341. Importador/exportador `.sks`,
  `Configs`, recursos de nombres y consumidores inspeccionados en el DEX.
- Función ARM64 `libcrypto.so:0xd9c40` ejecutada para versiones `1`, `341`,
  `2026.10.21` y `synthetic-v2`. SHA/KDF nativos ejecutados; operaciones C++ de
  strings y callback Java ChaCha modelados. Los cuatro resultados coinciden con
  `field_key`; no se presenta como ejecución completa de Android o de la app.
- `WKCFGSTART` de la imagen incluida abre con tag ChaCha válido. Las copias
  actuales `config.png` y `usr.png` se compararon completas con
  `tests/golden/socketclay_oracle.java`, implementado con JCA del JDK, de manera
  independiente del lector Python. Coinciden 1 servidor y 2 entradas de usuarios,
  incluidos 17 campos cifrados no vacíos (7 + 10), vacíos y metadatos.
- No se guardaron esas copias ni sus valores en Git. El archivo
  `tests/golden/socketclay_vectors.json` contiene solo información sintética:
  20 campos directos/envueltos en cuatro versiones, 27 claves de servidor,
  siete de usuarios, cuatro tipos de servidor, tipos JSON y secciones desconocidas.
- Los `.sks` GCM/DES usan los vectores sintéticos Java independientes ya
  comprobados para el mismo importador Fenix/Jireh. No hubo exportaciones reales
  de SocketClay. Se prueban ambos CLI y la ruta compartida real del worker.

## Pruebas reproducibles

Desde la raíz, con dependencias instaladas en el mismo entorno Python que
utilizan los procesos aislados del worker:

```bash
PYTHONPATH=cloud/workers/python:. python -m unittest tests.test_http_socketclay tests.test_http_fenixvpn tests.test_http_jireh -v
PYTHONPATH=cloud/workers/python:. python -m unittest tests.test_cloud_c8_android_server_vpn -v
python scripts/cloud_c0_inventory.py --check
cd cloud/web
node --test tests/server-vpn-catalog.test.mjs tests/server-vpn-provider.test.mjs tests/server-vpn-version-sync.test.mjs tests/server-vpn-worker-contract.test.mjs tests/c10-catalog-push.test.mjs tests/c12-provider-controls.test.mjs
```

La suite nueva comprueba resultados completos del proceso aislado, CLI desde
fuera del repositorio, UTF-16 Java, versiones, tags alterados sin fallback CBC,
GCM sin fallback DES, padding/cabeceras, JSON ambiguo/no finito/profundo,
campos corruptos sin salida parcial, límites, icono original y descarga simulada.
El JDK es necesario para reproducir el oracle; la CI Ubuntu lo incluye.
La descarga simulada no demuestra disponibilidad de una URL real.

## Resultado de esta entrega

- **47 pruebas Python aprobadas**, incluidas 14 nuevas de SocketClay y
  regresiones Fenix/Jireh e integridad de la integración Android existente.
- **41 pruebas Node aprobadas** para catálogo, fuentes existentes, sincronía de
  versión, avisos, contratos de worker y controles de proveedores.
- Copias incluidas `config.png`/`usr.png`: igualdad completa con el oracle Java
  también a través del trabajador aislado y CLI real con archivo y stdin.
- Matriz C0 verificada sin cambios y `git diff --check` correcto.
- No se afirma que CI de GitHub ya haya terminado ni que los endpoints remotos
  hayan sido comprobados: estos resultados son de la validación local descrita.

## Pendiente y límites

La revisión automática rechazó las consultas externas a los catálogos de
servidores y usuarios por la posible presencia de credenciales y la falta de
una autorización explícita para acceder a esas fuentes. No se repitieron por
otro host o herramienta. El contenido remoto, sus versiones y redirecciones
**no están validados**. Se conserva `remote:null`, sin broker público habilitado.
La validación remota y la habilitación posterior requieren una nueva comprobación.
No se ejecutó el APK en Android ni se certificó exportación/roundtrip `.sks`.
No se fusionó, desplegó, compiló ni publicó una APK como parte de este trabajo.
