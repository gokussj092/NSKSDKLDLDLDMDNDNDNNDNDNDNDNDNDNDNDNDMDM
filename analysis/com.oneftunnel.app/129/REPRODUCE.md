# Reproducir — 1FTunnel 0.7.3 (build 129)

Desde la raíz del repo. La contraseña real del archivo de Pedro **no** se
escribe en ningún comando: solo vía variable de entorno `ONEFT_PW`.

## 1. Pruebas del expediente (sin archivo real)

```bash
# Fixture sintético CFG1 v6 + contraseña (se genera si falta)
python analysis/com.oneftunnel.app/129/tools/make_fixture_v6.py

# Fixtures sintéticos CFG1 v1–v5 + contraseña (regresión: la corrección
# AÑADE v6 sin quitar v1–v5; se generan si faltan)
python analysis/com.oneftunnel.app/129/tools/make_fixtures_v1_v5.py

# Suite: 8 tests (self-test del repo 12/12, fixture v6+contraseña,
# PASSWORD_REQUIRED, AUTH_FAILED, apertura del worker en v6,
# apertura del worker en v1–v5 sin regresión, tamper, hash)
python -m unittest discover -s analysis/com.oneftunnel.app/129/tests -v

# Verificación contra la fixture (contraseña sintética "test-only")
ONEFT_PW=test-only python analysis/com.oneftunnel.app/129/tools/verify_073.py \
  --file analysis/com.oneftunnel.app/129/tests/fixtures/v6_password.1ftnl \
  --so071 <ruta>/liboneftunnel-security.so.071 \
  --so073 <ruta>/liboneftunnel-security.so.073

# Comparación DEX 0.7.1 vs 0.7.3 (requiere androguard en el venv)
python analysis/com.oneftunnel.app/129/tools/dex_compare.py \
  <classes-0.7.1.dex> <classes-0.7.3.dex>
```

## 2. Verificación del archivo real (estructura y códigos, sin valores)

```bash
# Positiva: 1FTunnel.py abre el archivo (GCM autenticado, CFG1 v6)
ONEFT_PW='<contraseña>' python analysis/com.oneftunnel.app/129/tools/verify_073.py \
  --file <ruta>/Free-23_0_jn8j.1ftnl \
  --so071 <ruta>/liboneftunnel-security.so.071 \
  --so073 <ruta>/liboneftunnel-security.so.073

# Negativa sin contraseña (esperado: PASSWORD_REQUIRED)
python decoders/Python/apps/OneFTunnel/1FTunnel.py --file <ruta>/Free-23_0_jn8j.1ftnl

# Ruta exacta del worker (tras la corrección: abre el archivo v6 con
# contraseña; authenticated True, isPartial False, CFG1 v6, SLOWDNS)
python3 -c "import os,json,sys; sys.stdout.write(json.dumps({'password': os.environ['ONEFT_PW']}))" \
  | python decoders/Python/apps/OneFTunnel/file_decoder.py --password-stdin \
      <ruta>/Free-23_0_jn8j.1ftnl
```

## 3. Inspección de la APK 0.7.3

```bash
unzip -o 1FTunnel-v0.7.3_1_0cgp.apk -d /tmp/ft073/apk
sha256sum /tmp/ft073/apk/lib/arm64-v8a/liboneftunnel-security.so
# androguard (venv ~/workspace/http-custom-update/venv):
python -c "import logging; logging.disable(logging.CRITICAL)
from androguard.misc import AnalyzeAPK
a,_,_ = AnalyzeAPK('1FTunnel-v0.7.3_1_0cgp.apk')
print(a.get_package(), a.get_androidversion_name(), a.get_androidversion_code())"
```

## 4. Head remoto (cableado del servidor)

```bash
git clone --depth 1 --branch ci/unity-ads-online-qa \
  https://github.com/gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM.git /tmp/spdecode-remote
git -C /tmp/spdecode-remote rev-parse HEAD  # nuevo head tras el push de la corrección
grep -n "range(1" /tmp/spdecode-remote/decoders/Python/apps/OneFTunnel/codec.py \
  /tmp/spdecode-remote/decoders/Python/apps/OneFTunnel/1FTunnel.py
# codec.py: range(1, 7) (v1-v6); 1FTunnel.py: range(1, 7)
grep -n "OneFTunnel" /tmp/spdecode-remote/cloud/workers/python/supplied_bridge.py
```

## Entorno

- Python 3.12.3; venv `~/workspace/http-custom-update/venv/bin/python` con
  PyCryptodome 4.4.0, androguard 4.1.4, unicorn 2.1.4.
- Sin red, sin Frida, sin captura, sin instalar nada en el teléfono.
