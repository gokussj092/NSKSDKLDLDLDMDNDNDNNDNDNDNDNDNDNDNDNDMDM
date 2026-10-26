# Validación TunnelDOOM 4.3.0

Resultado local: **32 pruebas Python y 348 Node aprobadas**, compilación
Next.js, inventario público y `validate_project.py` correctos. La suite
TunnelDOOM contiene 8 pruebas Python y 7 Node; CI del commit se sigue aparte.

## Reproducir

```sh
PYTHONPATH=cloud/workers/python:. python -m unittest \
  tests.test_tunneldoom_vpn tests.test_http_fenixvpn \
  tests.test_cloud_c8_vpn_registry tests.test_cloud_c0_inventory -v
python scripts/apk_analysis/tunneldoom_verify.py /privado/respuesta430.enc --worker
cd cloud/web
node --test --test-concurrency=2 tests/*.test.mjs
npm run build
```

JDK 17+ y dependencias Python del worker instaladas en su intérprete/venv.
El child aislado cambia HOME: no ve instalaciones pip --user del proceso
principal. No relajar su aislamiento para resolver dependencias locales.

## Evidencia real y sintética

- **Descargas APK:** 4.2.7/427 y 4.3.0/430, versión/paquete/certificado
  confirmados dentro del APK. Hashes en ANALYSIS/manifest. El certificado y
  el icono original 430 coinciden con 424. La descarga latest es mutable.
- **Real remoto 430:** HTTP 200 de la fuente literal, Version 473, 387 servidores,
  5031 campos cifrados no vacíos. Todo el texto exterior y JSON coinciden con
  JCA, CLI de descarga y worker aislado; segunda descarga CLI igual.435343
  bytes de JSON completo, fuera de Git. No es una muestra de primeros registros.
- **Real incluido:** Version 3, 1 plantilla de prueba vacía. Recurso idéntico
  en 424/427/430, 13 campos con cifrado aunque su plaintext sea vacío. No es
  un catálogo real de conexión ni sustituye el resultado remoto.
- **Sintético JCA:** 2 servidores / 24 campos no vacíos; Unicode, CRLF, flags,
  puertos, vacíos y desconocidos conservados. No es export real del APK.
- **Fallos:** campo corrupto, JSON duplicado, tipos incompatibles, NaN/overflow,
  profundidad, límites, Base64 y truncamiento: error sin salida parcial.
- **SKS:** GCM/DES JCA y XML exacto/duplicados en el worker canónico. Un tag
  inválido no reintenta DES. Regresiones Fenix conservan SocksIP d/v.
- **CLI:** stdin/archivo y descarga real nueva, URL fija sin redirecciones,
  archivo 0600 nuevo/no sobrescritura y errores sin contenido de entrada.
- **Web:** ficha e icono originales, controles persistentes preservando otros
  proveedores, sesión/consentimiento/gateway, DNS público fijado a TLS,
  redirecciones denegadas, JSON completo igual a structuredJson, rechazo
  de providerId/kind/arrays incoherentes y resultados parciales.

El Node nativo de este entorno no resuelve el host: EAI_AGAIN. El GET real
se comprobó con Python/HTTPS; transporte Node y gateway autenticado se
verifican con mocks. No se afirma una descarga Node externa desde VPS que
no se ha realizado. No hay cuentas del APK copiadas al código.

## Pendientes

- Exportación SKS real independiente del build nuevo y ruta UI activa.
- Android/Termux físicos y despliegue/VPS. OfflineSupported de SKS conserva
  su sentido histórico SocksIP y no certifica archivos TunnelDOOM offline.
- La API 427 de firma nativa y el endpoint HTTP 7676/GCM no se integran:
  la fuente actual 430 es pública y validada.
- Sin texto propietario ni importación Cloud individual por ID identificados.

No se fusiona, despliega ni publica APK/novedades automáticamente.
