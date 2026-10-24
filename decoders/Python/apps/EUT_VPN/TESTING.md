# Comprobación breve — EUT VPN 2.4.1

2026-10-22, build 370. Se inspeccionaron `yl`, `yz2`, `vz2`, `w62`, `m9a`,
`sza.b` y `NativeKeys`. El catálogo requiere una sesión Bearer; su constante
AES difiere de la del lector `.eut` histórico. No se sustituyó ese lector.

Por petición del usuario se realizan únicamente comprobaciones dirigidas:

- Tres pruebas Python: documento completo frente a vectores cifrados por JDK,
  salida íntegra del worker aislado, CLI por stdin fuera del repositorio,
  error remoto/no catálogo, último recurso corrupto y ausencia de sesión.
- Vectores públicos sintéticos en `tests/golden/eut_vpn_vectors.json`, generados
  con Java `AES/CBC/PKCS5Padding`, independientemente del lector. Incluyen dos
  versiones de SERVER, PAYLOAD y campos anidados/cifrados/desconocidos. No se
  descarta la segunda entrada como hace el consumidor de la app.
- 13 pruebas web dirigidas aprobadas: ficha pública desactivada, icono exacto
  y versión del catálogo, junto con las fichas existentes.
- HTTPS real autorizado: POST get-all-resources sin sesión → 401 Missing token;
  POST init-session vacío → 403 unsupported_integrity_env. No hubo catálogo
  real descifrado ni se utilizaron cuentas o conexiones VPN.

```bash
PYTHONPATH=cloud/workers/python:. python -m unittest tests.test_eut_vpn -v
cd cloud/web
node --test tests/server-vpn-catalog.test.mjs
```

No se ejecutaron suites completas, pruebas Android, flujo autenticado externo
con Bearer válido ni despliegue VPS. La integración remota sigue pendiente;
el funcionamiento del lector se ha comprobado con datos sintéticos JDK.
No se publican APK, tokens, identidades o respuestas privadas en Git/CI.
