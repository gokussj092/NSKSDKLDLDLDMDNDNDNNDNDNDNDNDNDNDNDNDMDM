# DeepTune-VPN v8 — REPRODUCE

Head de referencia: `5df9fc50cbe9e15067b687895aa27a29a3725e64`
(rama `ci/unity-ads-online-qa`, verificado con `git ls-remote`).

## 1. Versionado del APK (sin red)

```sh
python3 -c "
from androguard.core.apk import APK
a = APK('DeepTune-VPN_v8.apks')   # usar el base.apk extraído
print(a.get_package(), a.get_androidversion_name(), a.get_androidversion_code())
"
# esperado: tun.deep.vpn  v8  8
```

El `.apks` es un bundle: hay que extraer el `base.apk` antes de
analizarlo (los splits llevan solo ABI/recursos).

## 2. Re-corrida del catálogo en vivo (con red)

```sh
python3 deeptune_vpn_catalog.py -o catalogo.json
```

Esperado (2026-11-17): `Catalogo DeepTune-VPN v3.12: 6 servidores,
102 redes`, ~18 s en esta VM. La muestra entregada era v3.11 / 101
redes: la única diferencia legítima es la versión y las redes nuevas
del catálogo vivo. Comparación:

```sh
python3 -c "
import json
old = json.load(open('work/live.json'))
new = json.load(open('catalogo.json'))
print('versiones:', old.get('Version'), '->', new.get('Version'))
print('servidores iguales:', old.get('Servers') == new.get('Servers'))
print('redes:', len(old.get('Networks') or []), '->', len(new.get('Networks') or []))
"
```

## 3. Asset empaquetado (sin red)

```sh
python3 deeptune_vpn.py work/bundled.json -o bundled_out.json
# esperado (stderr): DeepTune-VPN v1.01: 9 servidores, 111 redes
```

## 4. Auditoría de campos (sin red, sobre el JSON descifrado)

```sh
python3 -c "
import sys, json
sys.path.insert(0, '.')
import deeptune_vpn_catalog as m
d = json.load(open('catalogo.json'))
fail = [(s.get('Name'), k) for s in d.get('Servers') or []
        for k in m.SERVER_FIELDS
        if s.get(k) and m.decrypt_field(s.get(k)) == s.get(k)
        and len(s.get(k)) >= 40]
print('campos de servidor que no abren:', len(fail))
print('ServerIPHost de muestra:', m.decrypt_field(d['Servers'][0].get('ServerIPHost', '')))
"
```

Esperado: 12 campos de servidor que no abren (9 en los 3 OVPN/SSH
+ 3 `SlowDNSKey` en los otros 3; `CustomCertificate` es texto plano
y no cuenta). `ServerIPHost` descifra a un hostname aunque el
script no lo incluya en `SERVER_FIELDS` (laguna documentada).

## 5. Tests del expediente (sin red, sin claves reales)

```sh
python3 -m pytest tests/test_method.py -v
# o: python3 tests/test_method.py
```

Usan solo claves de prueba sintéticas (`TEST-ONLY-...`) y el sobre
genérico de `tools/envelope.py` (misma construcción, parámetros
reducidos solo en el test). No tocan la red ni los scripts operativos.
Los scripts operativos no traen `--self-test`; su verificación es la
re-corrida en vivo + el asset empaquetado.
