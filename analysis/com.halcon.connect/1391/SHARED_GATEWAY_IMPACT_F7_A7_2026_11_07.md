# F7-A7 — Revisión de impacto del gateway compartido (2026-11-07)

**Expediente:** `analysis/com.halcon.connect/1391`.  
**Estado de esta revisión:** `PARTIAL — SECURITY_GATEWAY_REGRESSION_PENDING_ON_VPS`.  
**No altera la clasificación ni la evidencia del método de descifrado ya documentado en `RESULTS.md`.**

## Cambio indirecto detectado por CI F7-A0-P06

El comprobador de impacto ha identificado la cadena de importaciones estáticas:
`cloud/web/lib/rasp-policy.mjs` → `cloud/web/lib/v2-config.mjs` → `cloud/web/lib/c3-gateway.mjs`.

Estas son **dependencias compartidas de seguridad/encaminamiento**, no una prueba de que
el método específico del proveedor haya cambiado o dejado de funcionar. Se registra
el riesgo sin modificar código de proveedor, catalogadores ni métodos verificados.

## Evidencia de regresión disponible

- `Cloud C3 Security` sobre commit `1a4ac6e8`: **SUCCESS**, run
  https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42452183063.
- `Cloud C7 Integration and Parity` sobre el mismo commit: **SUCCESS**, run
  https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM/actions/runs/42452183243.
- `F7-A0 P06` identificó esta dependencia en `f7-a0-p06-gate.json`;
  se conserva la observación como pendiente documental.

**Límite de evidencia:** esas pruebas de CI son generales y no representan un
GET real de este proveedor después del cambio, ni una prueba de transporte en
el VPS ni una verificación de conectividad VPN. No se reclasifica como
`VERIFIED_REAL` ninguna funcionalidad adicional.

## Criterios para cerrar este pendiente

1. Tras aprobar la CI vigente, revalidar en un entorno privado la ruta efectiva
   del proveedor y la política RASP/V2 (autenticación, errores, sin regresiones).
2. Confirmar que el JSON de catálogo y las rutas de transporte siguen siendo
   compatibles con los oráculos y hashes autorizados previamente archivados.
3. Guardar `observed_at`, versión del servicio, comandos sanitizados y salida
   de pruebas en el expediente de esta aplicación/build conforme a
   `analysis/METHOD_EVIDENCE_POLICY.md`.
4. Si la prueba real no se puede ejecutar, conservar `PENDING` para esta
   ruta compartida; **no** modificar el decodificador de VPN por un gate documental.

**No se ejecutaron herramientas de Work, APK de terceros ni llamadas remotas
durante esta revisión documental. No se añaden claves, tokens ni datos VPN.**
