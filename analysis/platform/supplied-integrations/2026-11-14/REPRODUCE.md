# Reproducir desde la raíz del repositorio

Usar Python 3.12 con requirements.txt del proyecto y npm ci en cloud/web.

```bash
python analysis/platform/supplied-integrations/2026-11-14/tools/build_registry.py
python scripts/cloud_formats_catalog.py
python -m unittest tests.test_supplied_integrations tests.test_cloud_c8_vpn_registry tests.test_cloud_c8_worker_integration tests.test_cloud_c2_text tests.test_cloud_server_vpn_new tests.test_dtunnelmod tests.test_oneftunnel tests.test_v2box_password tests.test_mm_tunnel
cd cloud/web
node --test tests/supplied-integrations.test.mjs tests/file-formats.test.mjs tests/http-custom-online.test.mjs tests/server-vpn-catalog.test.mjs tests/server-vpn-worker-contract.test.mjs tests/mm-tunnel.test.mjs tests/thailand-kham.test.mjs tests/catalog-provider-check.test.mjs tests/text-format-catalog.test.mjs
npm run build
```

Las pruebas de Node que ejecutan el worker usan python3; SPC_QA_PYTHON permite seleccionar un virtualenv de QA. Todas las peticiones de esas pruebas usan transporte simulado; las muestras se descifran con el subprocess real. No se emulan veredictos Play Integrity.

Las muestras existentes se leen en su ubicación original; no se copian perfiles privados al expediente. No ejecutar los flujos de registro/integridad de proveedores para sustituir credenciales ausentes.

## Controles de los catálogos pendientes (revisión posterior)

Desde la raíz del repositorio:

```bash
node analysis/platform/supplied-integrations/2026-11-14/tools/check_catalog_controls.mjs
cd cloud/web
node --test tests/catalog-pending-controls.test.mjs tests/c12-provider-controls.test.mjs tests/admin-provider-maintenance.test.mjs tests/server-vpn-version-sync.test.mjs tests/supplied-integrations.test.mjs tests/server-vpn-catalog.test.mjs tests/c6-admin.test.mjs tests/catalog-provider-check.test.mjs tests/server-vpn-worker-contract.test.mjs
npm run build
```

El primer comando guarda solo conteos y alcance en generated/catalog-controls-proof.json. No ejecuta peticiones de proveedores ni cambia el estado de producción. Las pruebas cubren estados antiguos, activación de catálogos desactivados por defecto, reinicio del módulo, reconciliación de despliegue, requisitos técnicos ausentes, mantenimiento y rechazo de overrides inválidos. Para las pruebas del worker, Python debe tener las dependencias del proyecto; también se puede seleccionar con SPC_QA_PYTHON.
