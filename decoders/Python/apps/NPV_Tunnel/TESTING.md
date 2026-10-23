# Comprobaciones de actualización

**16 Python / 15 Node aprobadas**, enfocadas en contraseña, diagnóstico de
destinatarios y regresiones v5 app-key/npvs1. Sin suites completas.

- Archivo passphrase real: JSON completo igual a JDK independiente (ECDSA,
  PBKDF2, metadatos, contexto, HMAC y las 16 AEADs del inventario), referencia de
  reconstrucción/npvs1 separada, CLI fuera del repo y worker aislado.
- Nueve campos internos `npvs1:` recuperados sin transformar valores opacos.
- Muestras recipient aportadas: firma válida, punto P-256 válido y fingerprint
  coincidente; ambas requieren privada. No se afirma descifrado recipient/v6.
- Casos sintéticos: Unicode/NUL, contraseña hasta 4096 bytes con escapes JSON,
  ausencia/error de contraseña, clave pública incorrecta, framing y tags
  alterados, firma errónea, límites PBKDF2 y todas las truncaciones.
- Worker HTTP local autenticado real; gateway con transporte controlado.
  Sin prueba VPS, importación Android, sesión VPN o binarios reales en CI.

```bash
PYTHONPATH=. python -m unittest tests.test_npvs_protected \
  tests.test_npvs_v5.PrimitiveTests tests.test_npvs_v5_embedded \
  tests.test_cloud_c8_npvs_error_classification -v
node --test cloud/web/tests/c3-security.test.mjs
```

Los casos v6 sintéticos comprueban únicamente framing y diagnóstico. La
regresión real histórica de 107 registros sigue siendo opcional con su archivo
privado original; no se sustituye por estas muestras nuevas. Oracles/generadores
en `tests/golden/npvs_protected*`; comandos privados en RESTORE.md.
