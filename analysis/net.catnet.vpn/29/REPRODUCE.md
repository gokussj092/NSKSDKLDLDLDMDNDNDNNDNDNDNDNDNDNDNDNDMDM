# Reproducir el build Play aportado

Python3.12/JDK21/Node22; en la investigación Python3.12.14, OpenJDK21.0.13 y Node24.22.1. Preparar venv con requirements.lock.txt. Usar APKS autorizado y carpetas privadas fuera del checkout.

~~~bash
python analysis/net.catnet.vpn/29/tools/prepare.py /ruta/privada/CATNET.apks /tmp/catnet29-private
python analysis/_intake/austro-cat-2026-11-09/tools/decompile.py /tmp/catnet29-private
python analysis/net.catnet.vpn/29/tools/probe.py /tmp/catnet29-private
python -m unittest tests.test_catnet_vpn tests.test_catnet_retry -v
(cd cloud/web && node --test tests/catnet-vpn.test.mjs)
~~~

Opcional con copia autorizada27: python analysis/net.catnet.vpn/29/tools/compare_builds.py /ruta/privada/build27.apk /tmp/catnet29-private/base.apk --report /tmp/catnet29-private/diff.json. Los hashes de referencia están en generated/build-diff.json.

Si el sondeo vuelve a descargar servers.bin, comprobar el JSON entero mediante analysis/net.catnet.vpn/27/tools/verify.py, que conserva el oráculo Node/CLI/worker. No sustituir una descarga fallida por fixtures ni una copia vieja. No inventar sesión/Play token cuando el proveedor exija dispositivo.
