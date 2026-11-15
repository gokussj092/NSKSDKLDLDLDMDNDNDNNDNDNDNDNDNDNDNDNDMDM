# Reproducción desde la raíz del repositorio

Python3.12 y dependencias de requirements.lock.txt; JDK21 y Node22 (24.22.1 local). Mantener proxy/TLS heredados. Inputs/salidas reales en carpetas privadas fuera del repo.

~~~bash
python analysis/com.fleet.vpn/25/tools/acquire.py /tmp/litron25-private
python analysis/_intake/austro-cat-2026-11-09/tools/decompile.py /tmp/litron25-private
python analysis/com.fleet.vpn/25/tools/inspect_apk.py /tmp/litron25-private
python analysis/_intake/catnet-play-litron-2026-11-09/tools/probe_litron.py /tmp/litron25-private/catalog.bin
python analysis/com.fleet.vpn/25/tools/verify.py /tmp/litron25-private/catalog.bin --worker --report /tmp/litron25-private/proof.json
python analysis/com.fleet.vpn/25/tools/verify.py /tmp/litron25-private/embedded.bin --worker --report /tmp/litron25-private/embedded-proof.json
python -m unittest tests.test_litron_vpn -v
(cd cloud/web && node --test tests/litron-vpn.test.mjs)
~~~

Los hashes fijan el APK/build real; el primer descubrimiento usó version=latest. El sondeo solo conoce la fuente pública revisada. verify.py no llama main(), _load_crypto(), _prepare_json() ni media-scan del script original: compara sus funciones puras antes de la decoración editorial. El oráculo Java estándar no ejecuta ninguna clase del APK.

Regenerar solo fixtures propios: python analysis/com.fleet.vpn/25/tools/make_fixture.py analysis/com.fleet.vpn/25/tests/fixtures/vectors.json. No usar datos reales del catálogo para fixtures, logs o artefactos públicos. CLI operativo: python decoders/Python/apps/Litron_VPN/server_catalog_decoder.py; archivo o --stdin seleccionan ejecución sin red. El worker siempre llama run(bytes), sin descargas.
