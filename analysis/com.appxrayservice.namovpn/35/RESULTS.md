# Resultados

**VERIFIED_REAL**: GET original HTTP200, text/plain UTF8,72881bytes,
catálogo22.3 con14 Servers/13 Networks. SHA256
`578ad82fed747a2670a8fe4fb0abaeda16df60684581bec0a7e10e2d47aeee06`.
La segunda descarga desde el adaptador operativo tuvo los mismos bytes.
JSON entero igual entre referencia Java independiente, Python, CLI y worker
aislado, sin filtrar/truncar valores ni alterar Message/setOpenVPN/claves futuras.
No se encontró catálogo incluido; el template de V2Ray no se usa como sustituto.

**VERIFIED_SYNTHETIC**:10 pruebas Python y140 Node en16 archivos, todas pasan.
Incluyen generación independiente Java, UTF8/Unicode/CRLF, cuatro paddings,
clave incorrecta, corrupción, HTML, truncado, duplicados, NaN, esquema y límites;
petición fija, agente original, DNS/TLS, redirects, switches y paridad completa
del contrato. Los mocks son escenarios sintéticos, separados del GET real.

**Scripts y negativos conservados**:

- JADX1.5.6 termina3 con40 errores; ruta de catálogo y primitivas examinadas.
- `XAPK/icon.png` tiene contenido JPEG. El extractor v1 rechazó esa suposición;
  se conserva en history. El final copia sin modificar el PNG original de base.
- Primer pase Node139/140: expectativa de URL copiada incorrectamente en el test
  nuevo. Se corrigió a la fuente ya usada por producción/descarga real;
  pase final140/140. No se omitió ni relajó la comprobación del destino.
- Probe Node real: salida3/NETWORK_UNAVAILABLE/REMOTE_NETWORK_DENIED.

**SIMULATED_HTTP_REAL_BYTES**: broker Node recibe ciphertext real y resultado
real de worker, con DNS/HTTPS simulados, y aprueba documento completo22.3/14.
No equivale a HTTP real Node. **PENDING**: ese transporte en VPS, revisión humana
del PR y rollout. No se probaron conexiones VPN, vigencia de cuentas, archivos,
texto, exportación ni importación Android. El descifrado XXTEA no autentica.

Rama nueva desde main45db1d4: `feat/nuevas-integraciones`. Icono PNG192×192,
25421bytes, SHA2561b40b83a…312f7e; piso de catálogo66/62 fichas y256 formatos.
La constante de formato de10bytes está incorporada en codec.py por solicitud
del propietario; no hay variables externas nuevas para esta app. Ninguna
credencial HTTP fue necesaria. Solo el backend incorpora el método.

APK/SO, catálogos descifrados reales y registros con cuentas permanecen fuera de
Git. No hay cambios/build Android, merge ni despliegue. Firma: presencia V2/V3
y fingerprints inventariados; no equivalencia oficial Play ni última versión
certificada. Licencias transitivas y aprobación Fase7 siguen NEEDS_REVIEW;
el validador automático CI de evidencia sigue pendiente de implementación.
