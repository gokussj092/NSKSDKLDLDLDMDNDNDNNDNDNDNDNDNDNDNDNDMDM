# Reproducir Wolf build16 desde la raíz del repositorio

Usar un directorio privado fuera del checkout; no guardar APK, catálogo o salida
clara en Git. Python 3.12 y JDK21; dependencias fijadas en requirements.lock.txt.

~~~bash
python3 -m venv /tmp/wolf16-env
/tmp/wolf16-env/bin/pip install -r analysis/core.vpn3jx.xtreme/16/requirements.lock.txt
/tmp/wolf16-env/bin/python analysis/core.vpn3jx.xtreme/16/tools/acquire.py --out /tmp/wolf16-private
/tmp/wolf16-env/bin/python analysis/core.vpn3jx.xtreme/16/tools/inspect_apk.py /tmp/wolf16-private
python3 analysis/core.vpn3jx.xtreme/16/tools/install_go.py /tmp/wolf16-tools
(cd analysis/core.vpn3jx.xtreme/16/tools/oracle && /tmp/wolf16-tools/go/bin/go build -buildvcs=false -o /tmp/wolf16-oracle .)
/tmp/wolf16-env/bin/python analysis/core.vpn3jx.xtreme/16/tools/probe_catalog.py --output /tmp/wolf16-private/catalog.bin
/tmp/wolf16-env/bin/python analysis/core.vpn3jx.xtreme/16/tools/verify.py /tmp/wolf16-private/catalog.bin --elf /tmp/wolf16-private/native/libgojni.so --oracle /tmp/wolf16-oracle --worker --report /tmp/wolf16-private/proof.json
/tmp/wolf16-env/bin/python -m unittest discover -s analysis/core.vpn3jx.xtreme/16/tests -v
~~~

La adquisición se fija a versionCode16 y comprueba paquete/certificado. La
investigación inicial consultó version=latest; los hashes identifican los bytes
concretos. El lector nativo exige el hash de ARM32 observado y rechaza otra
biblioteca. El APK y la .so nunca se ejecutan.

inspect_apk.py documenta los mismos comandos efectivamente usados: JADX auto,
-Xmx2200m, 3 hilos, luego el resolver LSParanoid compartido y el inspector ARM32.
JADX puede salir con errores; solo se aceptan las evidencias explícitas del
camino de actualización y las verificaciones de criptografía independientes.

Para repetir el asset, extraer únicamente assets/configfile.json del base.apk
privado y usar el mismo verify.py. Su referencia está en generated/embedded-proof.json.

Las pruebas sintéticas se regeneran con tools/generate_vectors.py, usando el
oráculo compilado y --output analysis/core.vpn3jx.xtreme/16/tests/fixtures/build16-vectors.json.
No regenerar vectores a partir de datos reales de usuarios.

