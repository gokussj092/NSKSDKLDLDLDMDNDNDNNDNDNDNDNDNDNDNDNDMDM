# VertexSnipher — revisión de conexión

Estado: PARTIAL. Se conecta código aportado sin modificar su algoritmo ni atribuir una descarga remota nueva.

Registro detallado: [RESULTS.md](../../platform/supplied-integrations/2026-11-14/RESULTS.md).

Fuente y límites originales: [VertexSnipher](../../../decoders/Python/apps/VertexSnipher/README.md).

Reproducir la comprobación de importación y binding, sin red:

```bash
python analysis/platform/supplied-integrations/2026-11-14/tools/verify_provider.py vertexsnipher
```

Las pruebas de broker, worker aislado y regresión se ejecutan desde el expediente compartido. Las muestras faltantes y bloqueos se mantienen explícitos; esta comprobación no certifica al proveedor.

## Control administrativo del catálogo — 2026-11-14

Play Integrity e identidad genuina pendientes de captura autorizada; no existe broker completo. No se repitió investigación criptográfica ni validación remota en esta revisión.

Catálogo desactivado por defecto, activable y desactivable desde el panel. La elección se persiste de forma independiente; cuando faltan broker/configuración, el estado técnico permanece no disponible. Las rutas de archivo y texto no se modifican.

Prueba reproducible: `node analysis/platform/supplied-integrations/2026-11-14/tools/check_catalog_controls.mjs`. Evidencia compartida: `analysis/platform/supplied-integrations/2026-11-14/generated/catalog-controls-proof.json`.
