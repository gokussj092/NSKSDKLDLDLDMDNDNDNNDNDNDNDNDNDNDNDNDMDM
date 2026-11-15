# Reproducción desde la raíz del repositorio

Directorio privado fuera del checkout. Python3.12, JDK21 y Node22 (24.22.1 en la investigación local). Mantener proxy y validación TLS heredados. No ejecutar APK/DEX/SO.

~~~bash
python3 -m venv /tmp/austro15-env
/tmp/austro15-env/bin/pip install -r analysis/xyz.tekidoer.austroplus.vpn/15/requirements.lock.txt
/tmp/austro15-env/bin/python analysis/xyz.tekidoer.austroplus.vpn/15/tools/acquire.py /tmp/austro15-private
/tmp/austro15-env/bin/python analysis/_intake/austro-cat-2026-11-09/tools/decompile.py /tmp/austro15-private
/tmp/austro15-env/bin/python analysis/xyz.tekidoer.austroplus.vpn/15/tools/inspect_apk.py /tmp/austro15-private
/tmp/austro15-env/bin/python analysis/xyz.tekidoer.austroplus.vpn/15/tools/probe.py /tmp/austro15-private/catalog.bin
/tmp/austro15-env/bin/python analysis/xyz.tekidoer.austroplus.vpn/15/tools/verify.py /tmp/austro15-private/catalog.bin --worker --report /tmp/austro15-private/proof.json
/tmp/austro15-env/bin/python analysis/xyz.tekidoer.austroplus.vpn/15/tools/verify.py /tmp/austro15-private/embedded.bin --worker --report /tmp/austro15-private/embedded-proof.json
/tmp/austro15-env/bin/python -m unittest tests.test_austroplus15 tests.test_austroplus_vpn -v
~~~

La primera adquisición usó version=latest y se identificó build15; la receta conservada fija versionCode15. Base APK esperado: 72b5976c94cbfa757f414af0634fda922910ad998d651c1b256ff139b89d1691. Los catálogos reales cambian; los hashes registrados identifican únicamente la observación indicada, no todos los datos futuros.

Regenerar fixtures propios: python analysis/xyz.tekidoer.austroplus.vpn/15/tools/make_fixture.py analysis/xyz.tekidoer.austroplus.vpn/15/tests/fixtures/catalog15.json. Ejecutar pruebas desde fuera del directorio de datos privados; no publicar inputs ni salida clara.
