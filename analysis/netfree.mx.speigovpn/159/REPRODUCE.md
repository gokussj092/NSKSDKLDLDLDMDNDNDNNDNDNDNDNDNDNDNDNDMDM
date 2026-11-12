# Reproducir desde la raíz del repositorio

Python3.12 y requirements.lock.txt en un venv; OpenJDK21; host libsodium1.0.18; Node22 (24.22.1 local). Mantener proxy y TLS heredados. Las carpetas privadas deben estar fuera del checkout. No ejecutar APK, SO o DEX.

~~~bash
python analysis/netfree.mx.speigovpn/159/tools/acquire.py /tmp/speigo159-private
python analysis/_intake/austro-cat-2026-11-09/tools/decompile.py /tmp/speigo159-private
python analysis/netfree.mx.speigovpn/159/tools/inspect_apk.py /tmp/speigo159-private
python analysis/netfree.mx.speigovpn/159/tools/elf32.py /tmp/speigo159-private/libspeigoshield.so --start 0x17f20 --end 0x1871c
python analysis/netfree.mx.speigovpn/159/tools/recover_native.py /tmp/speigo159-private
python analysis/netfree.mx.speigovpn/159/tools/probe.py configs /tmp/speigo159-private/configs.bin
python analysis/netfree.mx.speigovpn/159/tools/probe.py ssh /tmp/speigo159-private/ssh.bin
python analysis/netfree.mx.speigovpn/159/tools/check_wire.py /tmp/speigo159-private
python analysis/netfree.mx.speigovpn/159/tools/verify.py /tmp/speigo159-private/configs.bin --worker --report /tmp/speigo159-private/configs-proof.json
python analysis/netfree.mx.speigovpn/159/tools/verify.py /tmp/speigo159-private/ssh.bin --worker --report /tmp/speigo159-private/ssh-proof.json
python analysis/netfree.mx.speigovpn/159/tools/verify.py /tmp/speigo159-private/embedded-configs.bin --worker --report /tmp/speigo159-private/embedded-configs-proof.json
python analysis/netfree.mx.speigovpn/159/tools/verify.py /tmp/speigo159-private/embedded-ssh.bin --worker --report /tmp/speigo159-private/embedded-ssh-proof.json
python -m unittest tests.test_speigo_vpn -v
(cd cloud/web && node --test tests/speigo-vpn.test.mjs)
~~~

La primera adquisición usó version=latest; el wrapper fija build159 y hash. No se instala ninguna dependencia por instrucciones del APK. probe.py conserva cuerpos con O_EXCL/0600; una segunda captura requiere otro nombre. La salida3 de JADX es parcial globalmente; el camino probado se verifica por hashes y firma/etiquetas reales. elf32.py soporta --arm para el CRT0x1f00; el código de formato es Thumb.

Las clases Java propias procesan TSV privado y solo devuelven material al verificador, que publica conteos/hashes. verify.py usa únicamente libsodium del sistema, nunca el SO Android. Fixtures ficticios: python analysis/netfree.mx.speigovpn/159/tools/make_fixture.py analysis/netfree.mx.speigovpn/159/tests/fixtures/vectors.json. Su firmante de prueba está separado y solo se sustituye en memoria dentro de tests; ni entorno, CLI ni worker aceptan una clave alternativa.

CLI configuraciones: python decoders/Python/apps/SpeiGo_VPN/server_catalog_decoder.py; CLI SSH: python decoders/Python/apps/SpeiGo_VPN/ssh_catalog_decoder.py. Cada uno acepta archivo o --stdin para no usar red; sin argumentos descarga solo su fuente. run(bytes) siempre es offline.
