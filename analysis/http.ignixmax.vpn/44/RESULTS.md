# IGNIX VPN MAX — revisión de conexión

Estado: PARTIAL. Se conecta código aportado sin modificar su algoritmo ni atribuir una descarga remota nueva.

Registro detallado: [RESULTS.md](../../platform/supplied-integrations/2026-11-14/RESULTS.md).

Fuente y límites originales: [IGNIX_VPN_MAX](../../../decoders/Python/apps/IGNIX_VPN_MAX/README.md).

Reproducir la comprobación de importación y binding, sin red:

```bash
python analysis/platform/supplied-integrations/2026-11-14/tools/verify_provider.py ignix-vpn-max
```

Las pruebas de broker, worker aislado y regresión se ejecutan desde el expediente compartido. Las muestras faltantes y bloqueos se mantienen explícitos; esta comprobación no certifica al proveedor.
