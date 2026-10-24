# Validación — Tx v2.17 (70), 2026-10-24

**42 pruebas Python / 72 Node aprobadas**. Cuatro documentos sintéticos y los
dos catálogos reales coinciden con la referencia independiente libsodium
Argon2id + JDK AES-GCM. Comparación de **6 documentos completos** y **4900
campos internos** (12 sintéticos + 657 del asset + 4231 del remoto), incluyendo
salida del worker aislado sin parcial. No se publican valores reales.

## Qué se verificó

- Exportación EO y JSON directo para perfil y catálogo: documento entero,
  tipos, vacíos, Unicode, claves desconocidas y cadenas que contienen JSON.
- Mutaciones de salt/nonce/tag; tags internos incorrectos y JSON duplicado
  autenticado no se ocultan mediante el lector histórico permisivo.
- Variantes `.tx` históricas con/sin AAD y regresiones de MM/Ultra/C8.
  Cuatro pruebas adicionales de fase C verifican inventario y 83 vectores
  Python de referencia, sin modificar ni compilar Android.
- CLI/stdin, API `run()`, worker privado y metadatos públicos sin credenciales.
- Descargador GET fijo: URL, appcode 27.0 derivado del APK, UA del recurso,
  sin URL del usuario ni redirecciones.
- Broker Node: DNS/IP pública, TLS, query exacta y política de redirecciones
  existentes; ficha PNG original y control individual persistente.
- C0 240 y C8 250 conservados; 20 overrides/adiciones C8. Solo `.tx` cambia
  de fuente en esta incorporación. Server VPN mínimo 40 / 40 fichas.
- Validador general, generación del catálogo público y diff limpios. Se
  conserva el SyntaxWarning preexistente de `docs/android/audit_decoders.py`.

El GET oficial devolvió **HTTP 200** y 922944 bytes. Aunque el servidor indica
Content-Type text/html, el cuerpo completo es Base64 autenticado y JSON válido:
**65.62, 27 servidores, 643 redes, 4231 campos**. Asset: **2.0, 23/66/657**.
El asset se abrió inicialmente en 16.24 segundos; tiempos de otros equipos
pueden variar. El remoto pasó por el presupuesto existente de catálogo de
120 segundos del worker. No se cambian los límites de otros proveedores.

## Comandos reproducibles

```bash
python -m pip install -r requirements.txt
python -m unittest tests.test_tx_tunnel tests.test_mm_tunnel tests.test_ultra_sandok \
  tests.test_cloud_c8_vpn_registry tests.test_cloud_c8_worker_integration \
  tests.test_android_c_ultra_parity -v
python validate_project.py
python scripts/cloud_formats_catalog.py
cd cloud/web
node --test tests/file-formats.test.mjs tests/server-vpn-catalog.test.mjs \
  tests/server-vpn-provider.test.mjs tests/server-vpn-worker-contract.test.mjs \
  tests/server-vpn-version-sync.test.mjs tests/c12-provider-controls.test.mjs
```

La referencia necesita `java` de JDK 17+ y libsodium del sistema. Reutiliza el
helper libsodium/JDK de los fixtures MM; no importa el codec de producción.
No ejecuta Android, JNI ni el SO del APK.

```bash
python tests/golden/tx_tunnel_reference.py > /tmp/tx-tunnel-vectors.json
cmp /tmp/tx-tunnel-vectors.json tests/golden/tx_tunnel_vectors.json
python scripts/apk_analysis/tx_tunnel_verify.py --worker
python scripts/apk_analysis/tx_tunnel_verify.py --worker \
  --catalog scripts/apk_analysis/work/tx-tunnel/configfile.json \
  --catalog scripts/apk_analysis/work/tx-tunnel/remote.enc
# Exportación real futura, aún no aportada:
python scripts/apk_analysis/tx_tunnel_verify.py --worker --file /ruta/perfil.tx
```

Último resultado privado, sin valores de configuración:

```json
{"completeIndependentDocuments":6,"independentInnerFields":4900,"isolatedWorker":true,"privateCatalogs":[{"version":"2.0","servers":23,"networks":66,"fields":657},{"version":"65.62","servers":27,"networks":643,"fields":4231}],"privateFile":false}
```

**Pendiente `.tx` real y prueba de importación en un teléfono.** El catálogo
remoto sí se validó, pero estos cambios no están desplegados por este trabajo.
No se compila/publica APK, no se modifica Android/C11 ni se fusiona el PR.
