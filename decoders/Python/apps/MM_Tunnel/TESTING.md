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
