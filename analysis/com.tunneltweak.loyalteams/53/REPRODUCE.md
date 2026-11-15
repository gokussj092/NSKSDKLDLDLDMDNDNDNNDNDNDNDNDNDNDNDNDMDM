# Reproducir Tunneltweak build53 desde la raíz

Python 3.12 y JDK21. Usar directorios privados fuera de Git.

~~~bash
python3 -m venv /tmp/tweak53-env
/tmp/tweak53-env/bin/pip install -r analysis/com.tunneltweak.loyalteams/53/requirements.lock.txt
/tmp/tweak53-env/bin/python analysis/com.tunneltweak.loyalteams/53/tools/acquire.py --out /tmp/tweak53-private
/tmp/tweak53-env/bin/python analysis/com.tunneltweak.loyalteams/53/tools/inspect_apk.py /tmp/tweak53-private
/tmp/tweak53-env/bin/python analysis/com.tunneltweak.loyalteams/53/tools/probe_catalog.py --output /tmp/tweak53-private/catalog.bin
/tmp/tweak53-env/bin/python analysis/com.tunneltweak.loyalteams/53/tools/verify.py /tmp/tweak53-private/catalog.bin --worker --report /tmp/tweak53-private/proof.json
/tmp/tweak53-env/bin/python -m unittest discover -s analysis/com.tunneltweak.loyalteams/53/tests -v
~~~

La adquisición inicial usó version=latest; la receta reproducible se fija a
versionCode53. Los hashes y el certificado identifican la muestra.

JADX 1.5.6 se invoca con auto, heap1600m y dos hilos. La salida descompilada queda
privada. El camino de solicitud y los parámetros de SecureConfigEncryption se
validan explícitamente; no se afirma que todas las clases hayan descompilado.

verify.py reutiliza tests/golden/tunneltweak_oracle.java sin modificarlo.
Compara el objeto completo, incluyendo data y announcement, con Python y el
worker real. No muestra ni guarda el JSON claro en el informe de evidencia.


## Recuperación automática y persistencia

~~~bash
python analysis/com.tunneltweak.loyalteams/53/tools/verify_auto_builds.py /tmp/tweak-auto-private
python -m unittest tests.test_tunneltweak_builds tests.test_tunneltweak -v
(cd cloud/web && node --test tests/tunneltweak-builds.test.mjs)
~~~

El servidor guarda /app/provider-control/tunneltweak-builds.json en el volumen provider-control existente; sobrevive a reinicios y actualizaciones de imágenes. No requiere un nuevo volumen ni recompilar APK. CLOUD_TUNNELTWEAK_BUILD_STATE_PATH permite una ruta privada alternativa controlada por el operador; en CI se usa runner.temp. El CLI usa esa variable o XDG_STATE_HOME/spdecode/tunneltweak-builds.json (por defecto ~/.local/state). El worker de descifrado puro nunca accede a este archivo ni a la red.

Para consultar: cat /app/provider-control/tunneltweak-builds.json dentro del contenedor web. No modificar auto.build durante uso normal. El historial no cambia el catálogo público ni incluye sus contenidos. Los seeds Python/web deben coincidir; lo comprueba el test. Si se borra el volumen, se pierde el historial y se vuelve a aprender desde el seed.
