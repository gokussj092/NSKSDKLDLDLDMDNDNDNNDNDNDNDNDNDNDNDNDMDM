# Validación vigente — MM Tunnel v1.10.30.2 (47)

Fecha2026-11-01. Prevalece sobre el resultado histórico build45 de abajo.

- **29 pruebas Python aprobadas**, sin omisiones:11 MM,1 registro C8,
  8 Enaa y9 ZiG. Incluyen compatibilidad histórica .mmt, GCM alterado,
  metadatos Base64, contextos desconocidos, tipos/duplicados/límites,
  CLI/stdin y worker completo; el POST exige hash, Content-Type y UA originales.
- **129 pruebas Node aprobadas**, sin omisiones: MM y regresiones de catálogos,
  proveedor, C12, sincronización, contrato worker, formatos y los proveedores
  Enaa/ZiG/ALFAISAL/IZPH/VIP. TLS/IP/DNS, POST/cuerpo/longitud/UA, rechazo de
  redirecciones, fuente fija, errores, sesión/cuota, switches persistentes y
  rechazo de worker parcial/inconsistente. Transportes Node simulados.
- **7 documentos completos** iguales a libsodium Argon2id + Java/JCA AES-GCM:
  seis fixtures sintéticos y el catálogo remoto real. **3411 campos distintos
  por documento** contrastados en total,3399 en el remoto. Worker aislado
  no parcial, presupuesto120s conservado. La lectura completa directa tardó
  87.63s en este entorno; otros entornos pueden variar.
- **CLI real sin argumento, fuera del checkout:** descarga HTTP200 nueva y
  descifrado completo igual al resultado independiente y al worker.
- Gateway probado con sesión/cuota y **todos los822713 bytes cifrados** y el
  JSON real validado de500239 bytes; transporte externo Node y respuesta HTTP
  interna del worker simulados. Siete comprobaciones de replay satisfactorias;
  no se afirma una nueva descarga externa Node ni despliegue en producción.
- `cloud_formats_catalog.py` aprobado: C0240,C8255; solo cambia el nombre
  público del lector .mmt a la versión vigente. Inventario Android congelado.
- `mm_tunnel_source_check.py`: verifica el XAPK actual y la receta nativa
  hash POST por cargas PC-relativas ARM, sin ejecutar código del APK.

```bash
PYTHONPATH=. python -m unittest tests.test_mm_tunnel tests.test_cloud_c8_vpn_registry \
  tests.test_enaa_tunnel tests.test_zig_tunnel -v
python scripts/cloud_formats_catalog.py
python scripts/apk_analysis/mm_tunnel_source_check.py /ruta/MM-Tunnel-v1.10.30.2-build47.xapk
python scripts/apk_analysis/mm_tunnel_verify.py --worker --catalog /ruta/MM-Tunnel-remote-2.46.enc
# Requiere Internet; stdout contiene datos VPN privados: guardar fuera de Git.
python decoders/Python/apps/MM_Tunnel/server_catalog_decoder.py > /ruta/privada/catalogo.json
cd cloud/web
node --test tests/mm-tunnel.test.mjs tests/server-vpn-catalog.test.mjs \
  tests/server-vpn-provider.test.mjs tests/c12-provider-controls.test.mjs \
  tests/server-vpn-version-sync.test.mjs tests/server-vpn-worker-contract.test.mjs \
  tests/file-formats.test.mjs tests/text-format-catalog.test.mjs \
  tests/enaa-tunnel.test.mjs tests/zig-tunnel.test.mjs \
  tests/alfaisal-tunnel-plus.test.mjs tests/izph-vpn-pro.test.mjs tests/vip-snipher-pro.test.mjs
```

Siguen pendientes exportación .mmt real, importación Android, fusión y despliegue.
No hubo compilación APK/AAB ni ejecución voluntaria de GitHub Actions.
Original/cifrado se conservan fuera de Git; recuperación y hashes en el handoff.

---

## Evidencia histórica build45 (no representa la descarga vigente)

# Validación — MM Tunnel v1.10.11.1 (45)

Fecha: 2026-10-24. Las pruebas guardan solo fixtures sintéticos. No hay muestra
`.mmt` real ni respuesta remota aceptada; no se certifica importación en Android.

## Resultados

- **39 pruebas Python aprobadas**: 10 de MM, 3 del localizador Go, 1 de registro,
  8 de Ultra/Sandok, 10 de integración C8 y 7 del catálogo remoto Android. Incluyen worker real aislado,
  tags/salt/nonce alterados, corrupción de campos internos, JSON no finito,
  duplicados, límites, stdout limpio, retrocompatibilidad y descarga POST fija.
- **69 pruebas Node aprobadas**: catálogo/iconos, proveedor/transporte, controles,
  sincronización de versiones y contrato del worker. MM permanece desactivado
  para descarga remota incluso con disponibilidad global habilitada.
- **7 documentos completos iguales** a una referencia independiente: seis
  sintéticos (perfil/catálogo × exportación/EO/JSON) y el asset real del APK.
  Comparación del JSON entero, no solo campos o nombres de servidores.
- **3,347 campos internos** contrastados mediante libsodium Argon2id y JDK
  AES-GCM: 12 en los fixtures y **3,335** en el catálogo real. El KDF del lector
  coincide además con el vector independiente de libsodium guardado en Git.
- El catálogo real, versión 1.01, contiene 34 servidores y 555 redes; el worker
  lo devuelve entero con `isPartial:false`, sin aumentar su presupuesto de 120 s.
- CLI/stdin, API `run()` y worker coinciden en los seis documentos sintéticos.
- `validate_project.py`, `cloud_formats_catalog.py` y `git diff --check` aprobados.
  El validador muestra un SyntaxWarning preexistente en `docs/android/audit_decoders.py`.

## Repetición

```bash
python -m pip install -r requirements.txt
python -m unittest tests.test_mm_tunnel tests.test_go_pclntab \
  tests.test_cloud_c8_vpn_registry tests.test_ultra_sandok \
  tests.test_cloud_c8_worker_integration tests.test_android_remote_formats -v
python scripts/cloud_formats_catalog.py
python validate_project.py
cd cloud/web
node --test tests/server-vpn-catalog.test.mjs tests/server-vpn-provider.test.mjs \
  tests/server-vpn-version-sync.test.mjs tests/c12-provider-controls.test.mjs \
  tests/server-vpn-worker-contract.test.mjs tests/file-formats.test.mjs
```

Referencia independiente: JDK 17+ con `java` y libsodium del sistema, además de
Python. `mm_tunnel_reference.py` no importa el codec de producción: usa
`crypto_pwhash` de libsodium, y el AES-GCM de JDK por lotes. Sus constantes y
framing se transcriben de las funciones Go verificadas. No ejecuta el SO del APK.

```bash
python tests/golden/mm_tunnel_reference.py > /tmp/mm-tunnel-regenerated.json
cmp /tmp/mm-tunnel-regenerated.json tests/golden/mm_tunnel_vectors.json
python scripts/apk_analysis/mm_tunnel_verify.py --worker
python scripts/apk_analysis/mm_tunnel_verify.py --worker \
  --catalog scripts/apk_analysis/work/mm-tunnel/configfile.json
# Cuando se disponga de una exportación autorizada real:
python scripts/apk_analysis/mm_tunnel_verify.py --worker --file /ruta/perfil.mmt
```

La última comprobación privada emitió únicamente:

```json
{"independentCompleteDocuments":7,"independentInnerFields":3347,"isolatedWorker":true,"privateCatalog":true,"privateFile":false}
```

## Red y alcance

El POST oficial devolvió HTTP 403 JSON. Se conserva el descargador fijo para
repetir una petición legítima, sin URL arbitraria o redirecciones. No se anuncia
el remoto como operativo. Tampoco se habilitan prefijos de texto inventados.
No se probaron ni cambiaron pantalla, APK, Play Console, VPS o novedades C11.

No se repite toda la CI Android: los cambios corresponden al lector Python,
metadatos del backend, documentación y herramientas de análisis. Las pruebas
anteriores son locales; el estado de GitHub Actions se revisa por separado.
