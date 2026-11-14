# DTunnel Mod — revisión de conexión

Estado: PARTIAL. Se conecta código aportado sin modificar su algoritmo ni atribuir una descarga remota nueva.

Registro detallado: [REPRODUCE.md](../../platform/supplied-integrations/2026-11-14/REPRODUCE.md).

Fuente y límites originales: [DTunnel_Mod](../../../decoders/Python/apps/DTunnel_Mod/README.md).

Reproducir la comprobación de importación y binding, sin red:

```bash
python analysis/platform/supplied-integrations/2026-11-14/tools/verify_provider.py dtunnel-mod
```

Las pruebas de broker, worker aislado y regresión se ejecutan desde el expediente compartido. Las muestras faltantes y bloqueos se mantienen explícitos; esta comprobación no certifica al proveedor.
