# DTunnel Mod — revisión de conexión

Estado: PARTIAL. Se conecta código aportado sin modificar su algoritmo ni atribuir una descarga remota nueva.

Registro detallado: [REPRODUCE.md](../../platform/supplied-integrations/2026-11-14/REPRODUCE.md).

Fuente y límites originales: [DTunnel_Mod](../../../decoders/Python/apps/DTunnel_Mod/README.md).

Reproducir la comprobación de importación y binding, sin red:

```bash
python analysis/platform/supplied-integrations/2026-11-14/tools/verify_provider.py dtunnel-mod
```

Las pruebas de broker, worker aislado y regresión se ejecutan desde el expediente compartido. Las muestras faltantes y bloqueos se mantienen explícitos; esta comprobación no certifica al proveedor.

## Credenciales integradas y prueba real

```bash
python decoders/Python/apps/DTunnel_Mod/DTunnel.py --url
python analysis/com.dtunnel.v2ray.pro/9/tools/probe_authorized_catalog.py --output analysis/com.dtunnel.v2ray.pro/9/generated/authorized-catalog-proof.json
python -m unittest tests.test_dtunnel_authorized_defaults tests.test_dtunnelmod tests.test_cloud_server_vpn_new tests.test_supplied_integrations
```

No se requiere archivo adicional de credenciales. El probe conserva únicamente hashes/conteos, nunca valores ni perfiles. El módulo Node de credenciales se genera con tools/build_registry.py del expediente compartido.

Tras npm run build en cloud/web, desde la raíz:

```bash
python analysis/com.dtunnel.v2ray.pro/9/tools/verify_public_assets.py --output analysis/com.dtunnel.v2ray.pro/9/generated/public-assets-proof.json
```
