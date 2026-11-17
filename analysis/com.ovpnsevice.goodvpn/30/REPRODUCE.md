# GOOD VPN 3.0 — REPRODUCE

Entorno: Python 3.12.3 (sistema). Sin red para los tests; con red para
la descarga en vivo. Sin secretos: ningún comando de este archivo lleva
claves, tokens ni endpoints con credenciales. La URL de descarga del
catálogo es pública (GitHub raw) y vive en el script operativo y en el
registro supplied, no en los fixtures.

## 1. Tests del expediente (sin red, sin secretos)

```sh
cd analysis/com.ovpnsevice.goodvpn/30
python3 -m unittest discover -s tests -v
```

Vectores SINTÉTICOS con claves de prueba generadas en el propio test
(`TEST-ONLY-KEY-16`, nunca las reales): round-trip XXTEA, round-trip
de campo interno Base64, esquema del fixture y negativos (vacío,
Base64 inválido, clave equivocada, truncado). Los fixtures son
sintéticos (`tests/fixtures/synthetic_catalog.json`, hosts
203.0.113.0/24 y example.org); un fixture sintético demuestra la
lógica implementada, NO prueba compatibilidad con una versión real ni
conectividad remota. El descifrado con parámetros reales está cubierto
por el `--url --summary` del script operativo y el `--self-test` del
script de archivos (ver RESULTS.md).

## 2. Self-test del script de archivos (sin red)

```sh
cd decoders/Python/apps/Good_VPN
python3 Good_VPN_archivos.py --self-test  # 3/3 ok (round-trip sintético cifrar -> descifrar)
```

`Good_VPN.py` no tiene `--self-test`; su verificación es la descarga
en vivo (punto 3) y `run()` sobre el cuerpo guardado:

```sh
python3 Good_VPN.py ~/workspace/catalogs/goodvpn/work/newgood.json --summary
# {"Version": "21.8", "Servers": 13, "Networks": 14, "undecoded_fields": []}
```

Los SHA-256 están en `MANIFEST.json`:

- `Good_VPN.py` — SHA-256 `1509c9b4e124a3012146aeb11c02af8a4b2d416e8681b0623410079e0b95e39a`
- `Good_VPN_archivos.py` — SHA-256 `a33af0655521296606b5b35e9ee284c531f6c0f97863df7a56983ca5fcf3d738`

## 3. Catálogo en vivo (con red; el script replica la petición de la app)

```sh
cd decoders/Python/apps/Good_VPN
python3 Good_VPN.py --url -o /tmp/live-good.json
python3 Good_VPN.py --url --summary
cmp /tmp/live-good.json ~/workspace/catalogs/goodvpn/live.json
```

La salida es el JSON de resultado limpio (regla 2026-11-15: solo datos
del catálogo, todo descifrado, sin APIs de descarga). Ojo: `-o` usa
`O_EXCL` y no sobrescribe: borrar el destino antes de repetir.

## 4. Archivos

```sh
cd decoders/Python/apps/Good_VPN
python3 Good_VPN_archivos.py ~/workspace/catalogs/goodvpn/work/newgood.json --summary
```

El cuerpo vivo guardado abre con el mismo formato que `profile.json`
(13 servidores, 14 redes). Falta un `profile.json` real extraído de un
teléfono.

## 5. Clave y URL (solo si cambia el formato)

La URL y la clave viven en `libapi-good.so` (4.312 B, en
`config.arm64_v8a.apk`): `MainDetail.a()` devuelve la URL,
`MainDetail.b()` devuelve la clave. Las cadenas de la app están
ofuscadas con R8; la re-implementación del desofuscador `jw1.x` está en
`~/workspace/catalogs/goodvpn/work/jw1.py` (verificada contra 8
constantes conocidas; sigue el bytecode DEX, no el jadx de `i2.m`,
que descompila mal los desplazamientos finales).

## 6. Herramientas de investigación (tools/)

Ver `tools/README.md`: `xxtea_pure.py` es una implementación genérica
de XXTEA (variante con longitud en la última palabra, delta como
parámetro, sin claves) usada solo por los tests del expediente. Ninguna
herramienta contiene claves ni endpoints.
