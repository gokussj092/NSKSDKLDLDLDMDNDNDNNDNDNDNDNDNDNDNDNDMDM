# MO VPN 1.0.6 — REPRODUCE

Entorno: Python 3.12.3 (sistema). Sin red para los tests; con red para
la descarga en vivo. Sin secretos: ningún comando de este archivo lleva
claves, tokens ni endpoints con credenciales. Las URLs de descarga del
catálogo son públicas (GitHub raw) y viven en el script operativo y en
el registro supplied, no en los fixtures.

## 1. Tests del expediente (sin red, sin secretos)

```sh
cd analysis/com.movpn.vpnth/6
python3 -m unittest discover -s tests -v
```

Vectores SINTÉTICOS con claves de prueba generadas en el propio test
(`TEST-ONLY-KEY-16`, nunca las reales): round-trip XXTEA, round-trip
del desplazamiento de caracteres de campo, esquema del fixture y
negativos (vacío, Base64 inválido, clave equivocada, texto truncado).
Los fixtures son sintéticos (`tests/fixtures/synthetic_catalog.json`,
hosts 203.0.113.0/24 y example.org); un fixture sintético demuestra la
lógica implementada, NO prueba compatibilidad con una versión real ni
conectividad remota. El descifrado con parámetros reales está cubierto
por el `--self-test` del script operativo (ver RESULTS.md).

## 2. Self-test del script operativo (sin red salvo el chequeo en vivo)

```sh
cd decoders/Python/apps/MO_VPN
python3 MO_VPN.py --self-test          # 8/8 ok (round-trip + asset pntvpn.json)
python3 MO_VPN_archivos.py --self-test # 9/9 ok (round-trip + asset pntvpn.json)
```

Los SHA-256 están en `MANIFEST.json`:

- `MO_VPN.py` — SHA-256 `c74b6cef42f4bf37adc712c80e0f945bb57ab381673da691af51c53cfe42e474`
- `MO_VPN_archivos.py` — SHA-256 `a879396cdc45acd564626a8fa8b82102d4e3b45bb0dd89112697b08f53dd41c9`
- `pntvpn.json` (asset) — SHA-256 `bf7cd941605094728714d1017aafa030121194a4e6096d17bb2336849229139b`

## 3. Catálogo en vivo (con red; el script replica la petición de la app)

```sh
cd decoders/Python/apps/MO_VPN
python3 MO_VPN.py --url -o /tmp/live-mo.json
cmp /tmp/live-mo.json ~/workspace/catalogs/movpn/live.json
```

La salida es el JSON de resultado limpio (regla 2026-11-15: solo datos
del catálogo, todo descifrado, sin APIs de descarga y sin `tokenKey`).

## 4. Archivos

```sh
cd decoders/Python/apps/MO_VPN
python3 MO_VPN_archivos.py pntvpn.json --summary
```

El asset `pntvpn.json` abre (13 servidores, 11 redes, 0 errores de
campo). Falta un `Config.json` real guardado por la app en un teléfono.

## 5. Valores nativos (re-emulación, solo si rota la clave)

Emulación Unicorn de los JNI de `libnative-sec.so` (arm64) en
`~/workspace/catalogs/movpn/work/emu_native.py` (arnés adaptado de PNT
VPN). Offsets JNI: `getApiUrl` 0x2ac4, `getAuthHash` 0x3c3c,
`getAesKey` 0x4d34, `getDelta` 0x5f30. La librería está en
`~/workspace/catalogs/movpn/work/arm64/` (extraída de
`config.arm64_v8a.apk`).

## 6. Herramientas de investigación (tools/)

Ver `tools/README.md`: `xxtea_pure.py` es una implementación genérica
de XXTEA (variante con longitud en la última palabra, delta como
parámetro, sin claves) usada solo por los tests del expediente. Ninguna
herramienta contiene claves ni endpoints.
