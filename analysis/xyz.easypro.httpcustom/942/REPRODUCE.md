# Reproducir — HTTP Custom 8.1.5 (build 942)

Venv: `~/workspace/http-custom-update/venv/bin/python` (pycryptodome,
argon2-cffi, msgpack, androguard 4.1.4, unicorn, capstone).

## 1. Versión del APK

```sh
unzip -o -q ~/workspace/user/files/HTTP_Custom_8.1.5_3_gnhh.apks \
  -d ~/workspace/http-custom-update/hc815/work/apks
~/workspace/http-custom-update/venv/bin/python -c "
from androguard.core.apk import APK
a = APK('~/workspace/http-custom-update/hc815/work/apks/base.apk')
print(a.get_package(), a.get_androidversion_name(), a.get_androidversion_code())"
# xyz.easypro.httpcustom 8.1.5 942
```

## 2. Inventario de los .hc + prueba contra el decodificador actual

```sh
cd ~/workspace/spdecode-patch/decoders/Python
~/workspace/http-custom-update/venv/bin/python HTTPCUSTOM.py \
  ~/workspace/user/files/test_open_2_7xqg.hc
# Error al ejecutar el decodificador: HTTP Custom HCCFG: UNSUPPORTED_SCHEMA
```

Estructura del sobre (sin descifrar contenido):

```sh
~/workspace/http-custom-update/venv/bin/python -c "
import sys; sys.path.insert(0, 'decoders/Python/apps/HTTP_Custom')
from codec import open_envelope
for f in ['test_bloqueo_normal_con_contrase_a_0_m46a','test_bloqueo_normal_1_aflj','test_open_2_7xqg']:
    env = open_envelope(open('/home/hatch/workspace/user/files/%s.hc' % f,'rb').read())
    print(f, '-> b=%s e=%s n=%s c=%s d=%s f=%s h=%s' % (env.get('b'), env.get('e'), env.get('n'), env.get('c'), env.get('d'), env.get('f'), env.get('h')))"
# los 3 -> b=14 e=n19 n=942 c=s1 d=h1 f=['ssh', 'profiles'] h=1/0/0
```

Detalle completo: `tools/hc-inventory.md` + `tools/hc-inventory.json`.

## 3. Sonda de la KDF interior n19

```sh
cd ~/workspace/http-custom-update/hc815/work
~/workspace/http-custom-update/venv/bin/python probe_n19.py
# control 934: 2/35 (abre con la n15 documentada)
# objetivo n19: 0/35 (ninguna construccion candidata)
```

## 4. Diff Java y nativo

- Java: `tools/java-diff.md` (jadx 1.5.3; descompilado 8.1.5 en
  `~/workspace/http-custom-update/hc815/work/jadx-out/`, log
  `~/workspace/http-custom-update/hc815/work/jadx815.log`).
- Nativo: `tools/native-diff.md` (.so nuevas en
  `~/workspace/http-custom-update/hc815/work/native/`).

## 5. Verificación de la fusión n19 (2026-11-26)

Staging: `~/workspace/repo-integration/staging-hc942/` (rutas relativas del
repo). Árbol de pruebas: copia del repo en `/tmp/hc942-testtree` con los
archivos de staging superpuestos (el worktree no se toca).

```sh
# py_compile de los archivos fusionados
~/workspace/http-custom-update/venv/bin/python -m py_compile \
  ~/workspace/repo-integration/staging-hc942/decoders/Python/apps/HTTP_Custom/codec.py \
  ~/workspace/repo-integration/staging-hc942/decoders/Python/apps/HTTP_Custom/crypto.py

# Apertura 942 (árbol de pruebas; codec, HTTPCUSTOM.run y file_decoder.run)
cd /tmp/hc942-testtree
~/workspace/http-custom-update/venv/bin/python -c "
import sys; sys.path.insert(0,'/tmp/hc942-testtree')
from decoders.Python.apps.HTTP_Custom import codec
for f in ['test_open_2_7xqg.hc','test_bloqueo_normal_1_aflj.hc']:
    o = codec.decrypt(open('/home/hatch/workspace/user/files/'+f,'rb').read())
    print(f, o['app_version'], len(o['config']), o['protections']['tunnelBanner'])
"
# Regresión: suite HC (mismo resultado en worktree intacto y árbol fusionado:
# 23 passed, 82 subtests passed, 5 failed preexistentes por 'C8 engine unavailable')
~/workspace/http-custom-update/venv/bin/python -m pytest tests/test_http_custom_899.py \
  tests/test_hc_legacy57.py tests/test_hc_sip_new_variants.py \
  tests/test_offline_hc_native_parity.py -q
# Textos hccloud:// (sin red): reescritura + bytes sin reescribir
cd ~/workspace/spdecode-patch/cloud/web && node --input-type=module -e "
import { parseHttpCustomLegacyReference, importHttpCustomReference } from './lib/c35-provider.mjs';
import fs from 'node:fs';
const raw = fs.readFileSync('/home/hatch/workspace/user/files/test_open_2_7xqg.hc');
const url = parseHttpCustomLegacyReference('hccloud://playsmarty/AbC123');
const out = await importHttpCustomReference(url, { download: async () => Buffer.from(raw) });
console.log(url, Buffer.compare(Buffer.from(out), raw) === 0);
"
```

Detalle y resultados: `tools/VERIFICATION_2026_11_26.md`.
