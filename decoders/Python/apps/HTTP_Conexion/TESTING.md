# Validación de HTTP Conexión

Desde la raíz, con el venv fijado en el expediente:

```sh
$PY -m unittest discover -s tests -p 'test_http_conexion*.py' -v
$PY analysis/com.doriaxvpn.unlimited/129/tools/refresh/run_checks.py private/http-conexion-refresh/checks
$PY analysis/com.doriaxvpn.unlimited/129/tools/refresh/verify_auto.py private/http-conexion-refresh
```

Resultado de la revisión 2026-11-04: 18 Python HTTP Conexión +9 Python Genis de regresión, 172 Node, todas aprobadas. Incluye JCA independiente, CLI y worker aislado, cambio de contraseña, caché/expiración, negativos de tags/HTML/JSON, rutas no aprobadas, credenciales restringidas a Google, sesión autenticada y un único reintento de descarga/descifrado.

La prueba real recibe configuración Firebase y el catálogo107/244/5325; compara todo el documento. La contraseña real actual coincide con la previa: su rotación se demuestra mediante un vector ficticio JCA y worker real, no mediante un cambio remoto inventado. Los fixtures no son perfiles VPN reales ni exportadores certificados.

Node real no completa el transporte en este ejecutor; el replay usa pareja/bytes/resultado reales con HTTP simulado y queda expresamente identificado. Debe probarse Node en VPS antes de desplegar. Recetas, fuentes, hashes y limitaciones: [REFRESH_2026_11_04.md](../../../../analysis/com.doriaxvpn.unlimited/129/REFRESH_2026_11_04.md).
