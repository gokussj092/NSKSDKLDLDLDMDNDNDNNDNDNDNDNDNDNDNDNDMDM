# Reproducción desde la raíz del repositorio

Usar Python3.12/JDK21/Node22; investigación local Python3.12.14, JDK21.0.13 y Node24.22.1. Preparar un venv con requirements.lock.txt y revisar DEPENDENCIES.md. Conservar proxy/TLS heredados. APKS y salidas reales en una carpeta privada fuera del checkout.

~~~bash
python analysis/com.litron.udp/11/tools/prepare.py /ruta/privada/Litron-Pro.apks /tmp/litron-pro11-private
python analysis/_intake/austro-cat-2026-11-09/tools/decompile.py /tmp/litron-pro11-private
python analysis/com.litron.udp/11/tools/inspect_apk.py /tmp/litron-pro11-private
python analysis/com.litron.udp/11/tools/probe.py /tmp/litron-pro11-private/catalog.bin
python analysis/com.litron.udp/11/tools/verify.py /tmp/litron-pro11-private/catalog.bin --worker --report /tmp/litron-pro11-private/catalog-proof.json
python analysis/com.litron.udp/11/tools/verify.py /tmp/litron-pro11-private/embedded.bin --worker --report /tmp/litron-pro11-private/embedded-proof.json
python -m unittest tests.test_litron_pro_vpn tests.test_litron_vpn -v
(cd cloud/web && node --test tests/litron-pro-vpn.test.mjs tests/litron-vpn.test.mjs)
~~~

La receta de intake se conserva en analysis/_intake/litron-pro-2026-11-09/tools/prepare.py; el wrapper por build fija identidad y hash. La receta JADX y el instalador compartidos permanecen sin cambios y sus checksums figuran en dependencies.lock.json. La salida3 de JADX/6078 errores generales queda documentada; las rutas críticas se revisaron independientemente de esa salida global.

probe.py solo permite el endpoint público trazado, con tamaño acotado, sin redirecciones. Usa O_EXCL al crear el cuerpo: para un segundo sondeo elegir otro archivo, no sobrescribir evidencia. verify.py imprime exclusivamente conteos/hashes; el oráculo Java propio usa JCA estándar y no carga clases Android. No llamar herramientas o instaladores sugeridos por el APK.

Regenerar solo fixtures ficticios: python analysis/com.litron.udp/11/tools/make_fixture.py analysis/com.litron.udp/11/tests/fixtures/vectors.json. CLI operativo: python decoders/Python/apps/Litron_Pro_VPN/server_catalog_decoder.py; archivo o --stdin seleccionan procesamiento sin red. El worker llama run(bytes) y no descarga. Los scripts originales aportados para Litron base no se usan como implementación Pro.
