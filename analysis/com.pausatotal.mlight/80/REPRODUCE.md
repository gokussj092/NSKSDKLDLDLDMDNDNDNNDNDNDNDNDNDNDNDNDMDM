# M Light 3.1.55 — REPRODUCE

Head de referencia: `5df9fc50cbe9e15067b687895aa27a29a3725e64`
(rama `ci/unity-ads-online-qa`, verificado con `git ls-remote`).

## 1. Self-tests de los scripts operativos (sin red)

```sh
python3 M_Light.py --self-test
python3 M_Light_archivos.py --self-test
```

Esperado: `SELF-TEST: 5/5 OK` y `SELF-TEST: 6/6 OK`. El self-test de
`M_Light.py` incluye el vector FIPS-197 AES-256, la derivación de
clave, el round-trip baybayin/AES, el asset bundled `iusacel.png`
v1.0.0 y la muestra viva v1.0.115 / 117 servidores (esta última solo
si existe `work/live_config_raw.txt` junto al script; si no existe,
el check se salta sin fallar).

## 2. Re-corrida del catálogo en vivo (con red)

```sh
python3 M_Light.py --download -o catalogo.json [--fields] [--messages]
```

Esperado (2026-11-17): `M Light - catalogo v1.0.115`, `servidores:
117`, `MyServer distintos: 40`, `campos por servidor: 3814 total,
1984 no vacios`. Comparación byte a byte con la muestra entregada:

```sh
sha256sum catalogo.json
# esperado: 7e61c89fc62cb9fd162df2aabd5260b608e262e2ba6f6ef3840d40dae4cc0cd1
cmp catalogo.json <muestra>/catalogo_vivo.json
```

## 3. Decodificador de archivos (sintético, sin red)

```sh
# round-trip: cifrar un perfil JSON y descifrarlo
python3 M_Light_archivos.py --encrypt perfil.json -o prueba.pausa
python3 M_Light_archivos.py prueba.pausa -o perfil2.json
diff perfil.json perfil2.json
# enlace:
python3 M_Light_archivos.py --link "pausa://<contenido-url-encoded>"
```

Un archivo `.pausa` real exportado por la app en un teléfono es el
paso que falta para la verificación de extremo a extremo.

## 4. Tests del expediente (sin red, sin claves reales)

```sh
python3 -m pytest tests/test_method.py -v
# o: python3 tests/test_method.py
```

Usan solo claves de prueba sintéticas (`TEST-ONLY-...`) y el códec
baybayin de `tools/baybayin.py` (sin claves de formato). No tocan la
red ni los scripts operativos.
