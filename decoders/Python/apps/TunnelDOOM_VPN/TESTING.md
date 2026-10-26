# Validación TunnelDOOM

Resultado local: **32 pruebas Python y 344 Node aprobadas**, compilación
Next.js, inventario público y `validate_project.py` correctos. Incluye ocho
pruebas nuevas Python y tres Node. CI del commit se verifica por separado.
Se corrigió una expectativa anterior de la prueba de novedades (versión de
fixture+1); no cambia `whats-new.json` ni publica una novedad TunnelDOOM.

## Reproducir

```sh
PYTHONPATH=cloud/workers/python:. python -m unittest \
  tests.test_tunneldoom_vpn tests.test_http_fenixvpn \
  tests.test_cloud_c8_vpn_registry tests.test_cloud_c0_inventory -v
python scripts/apk_analysis/tunneldoom_verify.py /privado/noobdev.txt --worker
cd cloud/web
node --test --test-concurrency=2 tests/*.test.mjs
```

Las pruebas requieren JDK17+ y las dependencias Python del worker instaladas
en su intérprete/venv. El child aislado cambia HOME y no ve instalaciones
`pip --user` del usuario del proceso principal. No relajar su aislamiento.

## Evidencia real y sintética

- **Real incluido:** res/raw/noobdev.txt Version3, 1 servidor, 13 campos
  cifrados no vacíos. Texto exterior completo idéntico a JCA, JSON entero
  idéntico a JCA, lector, CLI y worker aislado. Valores privados fuera de Git.
- **Sintético JCA:** 2 servidores / 24 campos no vacíos; vacíos, Unicode,
  CRLF, flags, puertos y claves desconocidas conservados. No es exportación
  real del APK. El oracle independiente transcribe las primitivas DEX.
- **Fallos:** campo corrupto, JSON duplicado, tipos incompatibles, NaN/overflow,
  profundidad, límites, Base64 y entrada truncada: error sin salida parcial.
- **SKS:** GCM y DES sintéticos de JCA, XML exacto/duplicados y worker canónico.
  Un tag GCM incorrecto no reintenta DES; las regresiones Fenix verifican la
  ruta histórica SocksIP `d/v`. No exige password personal ni HWID.
- **CLI:** stdin/archivo, GET literal con mocks, redirección rechazada,
  salida nueva0600 y no sobrescritura, mensajes sin contenido de entrada.
- **Web:** PNG original/hash, ficha desactivada incluso con availability=true,
  ID ausente de broker/controles remotos, extensión SKS compartida, C0/C8 y
  versión monotónica55. Se conservan formatos y prefijos existentes.

## Pendientes expresos

- Respuesta real del actualizador: inaccesible desde este entorno; HTTP503
  del proxy por fallo de conexión upstream. Los mocks no prueban disponibilidad.
- Exportación `.sks` real independiente de build424 y ruta UI activa.
- Android y Termux físicos. No se genera ni publica APK como parte de esta
  integración. `offlineSupported` histórico de SKS no certifica TunnelDOOM.
- No hay importador propietario de texto/Cloud por ID identificado.

No fusionar, desplegar ni publicar novedades por esta validación.
