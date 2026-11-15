# DTunnel Mod — revisión de conexión

Estado: PARTIAL. Se conecta código aportado sin modificar su algoritmo ni atribuir una descarga remota nueva.

Registro detallado: [RESULTS.md](../../platform/supplied-integrations/2026-11-14/RESULTS.md).

Fuente y límites originales: [DTunnel_Mod](../../../decoders/Python/apps/DTunnel_Mod/README.md).

Reproducir la comprobación de importación y binding, sin red:

```bash
python analysis/platform/supplied-integrations/2026-11-14/tools/verify_provider.py dtunnel-mod
```

Las pruebas de broker, worker aislado y regresión se ejecutan desde el expediente compartido. Las muestras faltantes y bloqueos se mantienen explícitos; esta comprobación no certifica al proveedor.

## Actualización autorizada de credenciales — 2026-11-14

Se integra el valor entregado por el propietario como default del script y del broker. El repositorio es público, circunstancia informada antes de publicar. Solo el código de backend contiene el valor; el catálogo y los activos web públicos no deben incluirlo.

Prueba real sanitizada: generated/authorized-catalog-proof.json. HTTP 200, 80.600 bytes, 49 perfiles y coincidencia completa con el worker aislado. No se almacena la respuesta privada nueva. Sin cambios del algoritmo de cifrado ni nuevas afirmaciones HMAC de autenticación VPN.

Validaciones de esta actualización: 33/33 pruebas Python, 49/49 pruebas Node y npm run build aprobados. La inspección de 179 archivos públicos, chunks de navegador y assets Android no encontró el identificador. El valor sí queda publicado en los archivos de código del repositorio público, como se autorizó expresamente.
