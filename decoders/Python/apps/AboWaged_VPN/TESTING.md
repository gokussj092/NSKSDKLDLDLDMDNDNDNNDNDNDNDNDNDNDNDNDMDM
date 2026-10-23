# Validación — AboWaged VPN 1.0

Comprobación del 2026-10-23, enfocada en este lector, sus rutas y controles.

- **11 pruebas Python aprobadas**: 10 del lector y una de inventario C8/C0.
  Incluyen 14 vectores JDK CBC/CFB, bloques 0/1/15/16/17 bytes, UTF-8/emoji/NUL,
  archivos sintéticos con y sin `MyPass`, servidor JSON interno, tipos nulos,
  campos desconocidos, UTF-16 UDP, límites y esquemas/cifrados incompatibles.
  CLI fuera del checkout y stdin, bot `.awg`, worker aislado y handler HTTP real.
- **68 pruebas Node aprobadas**: seis archivos enfocados. Broker autenticado
  de dos fuentes, errores de fuente, contrato completo, DNS/TLS/origen y URL
  fija, controles, PNG original grande, 37 fichas y versión monotónica que
  conserva versiones persistentes superiores y proveedores desactivados.
- **Paridad JDK completa**: JSON entero del catálogo inicial (1/1, v1.0),
  catálogo remoto (12/257, v4.6.3) y selector UDP (2), no solo conteos.
- CLI HTTPS vuelve a descargar ambos orígenes y coincide con las copias
  privadas completas. Bundle de **102521 bytes** igual en CLI, módulo y worker,
  `isPartial:false`, sin credenciales ni cuerpos reales publicados.
- **Cuatro wrappers ARM64 originales comprobados**: Jencrypt/Jdecrypt y
  Fencrypt/Fdecrypt, destinos Java, operaciones y constantes de clave iguales.
  JNI modelado y acotado; el AES se verifica mediante JDK, no como AES nativo.

```bash
python tests/golden/abowaged_generate.py
python -m unittest tests.test_abowaged_vpn tests.test_cloud_c8_vpn_registry -v
cd cloud/web
node --test tests/abowaged-vpn.test.mjs tests/server-vpn-provider.test.mjs \
  tests/server-vpn-catalog.test.mjs tests/server-vpn-version-sync.test.mjs \
  tests/c12-provider-controls.test.mjs tests/server-vpn-worker-contract.test.mjs
```

Después de conservar las muestras autorizadas fuera del repositorio:

```bash
python scripts/apk_analysis/abowaged_verify.py --worker \
  --catalog /ruta/noobdev.js --catalog /ruta/Elk.txt --udp /ruta/pickerver \
  --native /ruta/libwg-pro.so
# Añadir --file /ruta/perfil.awg cuando exista una exportación real.
```

Regenerar los fixtures requiere JDK 17+. Ejecutar tests/runtime necesita
PyCryptodome; no requiere herramientas de descompilación. La comprobación
nativa requiere las dependencias de `scripts/apk_analysis/requirements.txt` y
el SO con hash exacto. La suite completa no se ejecutó. No se probó una VPS
desplegada ni la importación de una exportación real `.awg` en Android.

Los dos archivos sintéticos demuestran que la clave no depende de `MyPass`,
pero no sustituyen el pendiente de una exportación real. Las capturas y
credenciales reales no se guardan en tests/CI. No se certifica autenticidad de
cifrados sin MAC ni compatibilidad con versiones futuras.
