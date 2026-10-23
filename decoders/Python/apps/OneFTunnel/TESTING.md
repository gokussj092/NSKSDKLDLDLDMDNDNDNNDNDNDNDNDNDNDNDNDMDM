# Validación 2026-10-23

- **9 pruebas Python aprobadas**: ocho de 1FTunnel y registro C8 congelado/C0.
  **13 pruebas Node aprobadas**, incluidas dos nuevas del gateway.
- **15 vectores JDK sintéticos**: contenedor v1–v3 × documento v1–v5; cuatro
  tipos de configuración, modos de bloqueo 0/1/2, dos certificados y slots,
  todos los transportes/modos de inyección, Unicode/NUL, null y vacíos.
  Regeneración JDK reproducible y comparación del JSON completo.
- Muestra real independiente del generador: **2904 bytes de texto → CFG1 de
  1995 bytes**, GCM aceptado, EOF exacto. JSON íntegro igual a DataInputStream,
  HKDF/HmacSHA256 y AES-GCM de JDK; CLI, worker archivo y texto iguales.
- **32 comparaciones KDF ARM64 originales**: dos slots para los 15 vectores
  y la muestra real. Callback HMAC/memoria modelados; límites en ANALYSIS.md.
- Worker HTTP local autenticado real, proceso aislado y CLI fuera del repo;
  igualdad de todos los campos, `isPartial:false`. Gateway Node usa transporte
  controlado; no se afirma prueba desde la VPS ni sesión VPN.
- Rechaza manipulación de salt/nonce/AAD/ciphertext/tag, framing truncado o con
  restos, versiones desconocidas, identidad distinta, booleans inválidos,
  cadenas corruptas/excesivas y documentos autenticados incompatibles.
- Contraseña ausente/incorrecta produce error seguro; no se registra ni pasa
  por argv/env. No se acepta HWID ni contraseñas para prefijos ajenos.

```bash
PYTHONPATH=. python -m unittest tests.test_oneftunnel tests.test_cloud_c8_vpn_registry -v
node --test cloud/web/tests/c3-security.test.mjs
java -XX:-UsePerfData tests/golden/oneftunnel_oracle.java > /tmp/oneftunnel_vectors.json
python scripts/apk_analysis/oneftunnel_verify.py --worker
# Con archivos privados autorizados fuera de Git:
python scripts/apk_analysis/oneftunnel_verify.py --input /ruta/perfil.1ftnl \
  --library /ruta/liboneftunnel-security.so --worker
```

Sin suites completas, escritura/importación Android de archivos sintéticos,
compilación APK o despliegue. Las pruebas Android de detección se amplían como
fuente, pero no se ejecutó instrumentación. Las revisiones antiguas y modos con
contraseña se certifican aquí con vectores sintéticos, no con archivos reales
aportados para cada combinación. Catálogo no identificado, pendiente.
