# Reproducir desde la raíz de SP-DECODE

Con Python 3.12, Node.js y los runtimes de los decodificadores locales:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip install pytest==9.0.2
npm ci --omit=dev
.venv/bin/python -m unittest tests.test_cloud_c2_hc tests.test_hc_legacy57 tests.test_hc_sip_new_variants tests.test_http_custom_899 tests.test_tunneltweak tests.test_tunneltweak_builds tests.test_generic_profiles_registry tests.test_config_batch_modules tests.test_independent_batch_registry tests.test_text_extra_dispatcher tests.test_v2box_password tests.test_access -q
.venv/bin/python -m pytest -q tests/test_xveon.py tests/test_xutunnel.py tests/test_telegram_cloud_decoders.py tests/test_cloud_c8_vpn_registry.py -k 'not real_link'
```

El bot de pruebas sustituye la API de Telegram por dobles locales. El
despachador ejecuta los lectores reales como subprocesos sobre fixtures
sanitizados. No hace falta introducir token, contraseña real ni HWID real.
