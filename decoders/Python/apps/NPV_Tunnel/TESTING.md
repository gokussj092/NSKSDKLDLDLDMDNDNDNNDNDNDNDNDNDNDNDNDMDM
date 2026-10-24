# Comprobaciones de actualización

## Nueva muestra normal y script de texto separado

- **Kurdo vip bunq.npvs**, 2050 bytes: NPVS v5, app-key 2/keyId 2, cero
  destinatarios; una configuración, 20 registros autenticados y 12 campos
  `npvs1:` internos abiertos. Todo el JSON igual a JDK, CLI fuera del repo y
  worker aislado sin credenciales, `isPartial:false`.
- **Cinco pruebas nuevas aprobadas** de `tests.test_npv_text`: detección de
  cinco aliases, JSON completo/listas/Unicode/tipos/vacíos, capas npvs1, errores,
  NPVS autenticado app-key/passphrase, diagnóstico recipient y CLI copiado
  fuera del checkout con `python -S` para probar stdlib sin paquetes externos.
- Los enlaces de prueba son sintéticos. `npvt-ssh` se contrasta además con el
  exportador/importador del APK; los otros cuatro prefijos carecen de muestras
  reales. No se certifican otras variantes cifradas por el nombre del esquema.
- Sin cambios del códec de archivos ni del router. La integración del nuevo
  script de textos queda para el siguiente chat por instrucción del usuario.

```bash
PYTHONPATH=. python -m unittest tests.test_npv_text -v
python scripts/apk_analysis/npvs_verify.py /ruta/normal.npvs --worker
```

## Comprobaciones de la entrega anterior

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
