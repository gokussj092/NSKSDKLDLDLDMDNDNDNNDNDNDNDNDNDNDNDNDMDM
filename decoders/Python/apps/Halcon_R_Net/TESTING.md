# Pruebas Halcon1391

- `python -m unittest discover -s tests -p test_halcon_r_net.py -v`:10 correctas.
- `python -m unittest discover -s analysis/com.halcon.connect/1391/tests -v`:12 correctas.
- `node --test cloud/web/tests/halcon-r-net.test.mjs cloud/web/tests/server-vpn-provider.test.mjs cloud/web/tests/server-vpn-worker-contract.test.mjs`:33 correctas.

Las suites versionadas son sintéticas; fixture de catálogo producido por
Java/JCA, UTF8, campos completos y desconocidos. Casos de claves ausentes,
GCM alterado, estructura parcial, HTML, codificación, duplicados, profundidad,
POST fijo, redirección, DNS privado, switches persistentes y contrato worker.

Prueba real separada: `tools/verify_real.py --download` descargó por la CLI y
comparó el documento entero con JCA y worker aislado: **635/101**. No se guardan
datos reales en fixtures ni Git. `tools/replay_real.mjs` verificó el transporte
Node simulado y el contrato del worker con esos bytes reales.

Node directo no pudo resolver/acceder al destino desde el entorno y devolvió
REMOTE_NETWORK_DENIED; causa registrada como restricción de red, no como fallo
de autenticación ni del proveedor. Prueba del VPS y Android pendiente.
