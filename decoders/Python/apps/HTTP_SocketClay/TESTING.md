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
npm test
```

La suite nueva comprueba resultados completos del proceso aislado, CLI desde
fuera del repositorio, UTF-16 Java, versiones, tags alterados sin fallback CBC,
GCM sin fallback DES, padding/cabeceras, JSON ambiguo/no finito/profundo,
campos corruptos sin salida parcial, límites, icono original y descarga simulada.
El JDK es necesario para reproducir el oracle; la CI Ubuntu lo incluye.
La descarga simulada no demuestra disponibilidad de una URL real.

## Validación remota autorizada

El usuario autorizó expresamente consultar servidores y usuarios el 2026-10-21.
El bloqueo previo de revisión quedó resuelto por esa autorización.

- Los enlaces originales del APK respondieron 302 hacia CDN firmado de Dropbox;
  ambas descargas terminaron con HTTP 200. Las fuentes directas fijas verificadas
  devolvieron bytes idénticos, sin redirecciones.
- Servidores: **157056 bytes, Version `107`, 86 registros, 663 campos cifrados
  no vacíos**. Usuarios: **1816 bytes, Version `10`, 2 entradas, 10 campos
  cifrados no vacíos**. Se compararon los JSON completos contra el JDK oracle;
  no solo nombres, recuentos o muestras de los primeros registros.
- La CLI real `--all` descargó ambas fuentes y devolvió exactamente esos dos
  documentos completos. La misma comparación pasó en el trabajador aislado.
- Flujo local autenticado: petición → broker y dos fuentes fijas simuladas con
  los bytes remotos autorizados → HTTP privado real → proceso aislado → respuesta
  completa. Igualdad total con el oracle y `isPartial:false`.
- El DNS nativo Node de este entorno devolvió `EAI_AGAIN`. Por ello las pruebas
  del transporte Node DNS/IP/TLS/redirecciones fueron controladas; las descargas
  externas reales fueron por Python/HTTPS. No se afirma una prueba externa desde
  la VPS, que no fue desplegada en este trabajo.
- Ningún catálogo ni valor descifrado real se incluye en Git/CI. Solo vectores
  sintéticos, estadísticas de validación y parámetros fijos del motor.

## Resultado de esta entrega

- **50 pruebas Python aprobadas**, incluidas 17 de SocketClay y regresiones
  Fenix/Jireh e integridad de la integración Android existente.
- **152 pruebas Node aprobadas**: toda la suite web, incluidas siete pruebas
  nuevas de descargas duales, petición autenticada, ausencia de éxitos parciales,
  coherencia de resultado, fuentes fijas y transporte del paquete.
- Se comprobó la activación/desactivación del proveedor y la elevación de la
  versión persistente aunque la tarjeta y el icono ya existieran.
- Matriz C0 verificada sin cambios y `git diff --check` correcto.
- Estos resultados son locales. La finalización de CI de GitHub no se presupone.

## Límites restantes

No se ejecutó el APK en Android ni se certificó exportación/roundtrip `.sks`.
No se fusionó, desplegó, compiló ni publicó una APK como parte de este trabajo.
Los presupuestos de tamaño/tiempo generan errores explícitos; nunca se recortan
catálogos ni se silencian fuentes omitidas. Si los catálogos reales cambian,
la descarga usa sus documentos actuales y las claves de sus propias versiones.
