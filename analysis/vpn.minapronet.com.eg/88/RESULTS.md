# RESULTS — MinaProNet 88.0.0 (versionCode 88)

Fecha de las pruebas: 2026-11-14/15 y actualización 2026-11-17. Entorno: Python 3.12.3 del sistema, solo stdlib, sin red
para los tests de este expediente. Las pruebas en vivo citadas se hicieron 2026-11-14/15 y 2026-11-17 con
los scripts operativos (ver `~/workspace/catalogs/minapronet/` y NOTES.md).

## 1. Estado probado por via

| Via | Estado | Evidencia |
|---|---|---|
| catalog (MinaConfig) | FAILED | Updater en vivo VACIADO por el vendedor (HTTP 200, 14 B, 'hello world..' el 2026-11-14; luego HTTP 404, archivo borrado; jsDelivr aun sirve copia en cache). Respaldo de emergencia 404. El endpoint del sitio responde update_required para v88/v89: hoy NO entrega config. El METODO esta verificado por control: k() abre en vivo slowdns_config.json (v4, 7 servidores, 54 redes). |
| catalog (servidores públicos) | VERIFIED | v2ray-verified.json en vivo: 205 entradas, 205 online, 31 países (153 ss, 29 trojan, 17 vless, 6 vmess), re-corrido 2026-11-17; lista de servidores y resumen idénticos a `live.json`. Cableado en esta actualización (ver sección 6). |
| files | VERIFIED_SYNTHETIC | .mina (Manager.exportTest/importTest): muestra SINTETICA muestra.mina (3046 B) sellada y reabierta con JSON identico; sin .mina REAL exportado por la app. 68 campos; caducidad por t (ms); pw y HWID son campos del JSON, no parte de la clave AES. |
| text | NOT_APPLICABLE | Sin esquema propio; enlaces V2Ray estandar pegados en la interfaz; Manager.dcx/dpt aplica ROT-1 internamente. Nada nuevo para SP-DECODE. |
| export | PENDING | Nube por clave: Firebase Storage, <clave de 27 caracteres>.mina. Validado en vivo con clave inventada -> CLOUD_KEY_NOT_FOUND (HTTP 404); falta una clave real. Sincronizacion servidor->app (nativeFetchServerConfig): URL del canal no recuperada. |

## 2. Verificacion en vivo (oraculo independiente)

Updater en vivo vacio (200, 14 B) luego 404; sitio update_required (v88/v89); control k() sobre slowdns_config.json en vivo (v4, 7/54); servidores publicos 213/33 paises (11-14) -> 234/35 (11-15) -> 205/31 paises (11-17).

Self-tests de los scripts operativos: Catalogo 21/21, archivos 12/12 (scripts operativos, 2026-11-17; `all_ok` incluido en el conteo de líneas OK: 22 y 13 líneas OK respectivamente).

## 3. Tests de este expediente (sinteticos, sin red)

- `python3 tests/test_method.py` (unittest): **8 tests, OK** (exit 0).
- `python3 tests/test_public_servers.py` (unittest, nuevo 2026-11-17): **5 tests, OK** (exit 0).
- `python3 tools/verify.py`: **OK** (exit 0).
- Fixtures en `tests/fixtures/`: vectores SINTETICOS generados con claves TEST-ONLY
  (`bytes(range(...))`); no contienen material real, servidores reales con claves ni perfiles reales.
  `tests/fixtures/public_servers_fixture.json` es una lista SINTETICA de 3 servidores
  (hosts 203.0.113.x, TEST-NET; contraseñas `TEST-ONLY-...`).
- pytest NO esta instalado en este entorno; los tests son `unittest` (stdlib) y compatibles
  en forma con pytest cuando este instalado.

Clasificacion: lo anterior es **VERIFIED_SYNTHETIC** para la logica del formato.
Lo en vivo es **VERIFIED_REAL** solo donde la via lo indica arriba; donde la via es
PENDING/FAILED, nada sintetico la convierte en verificada.

## 4. Pruebas negativas (incluidas en tests/test_method.py y test_public_servers.py)

- Entrada truncada -> `ValueError`.
- Base64 invalido / HTML inesperado -> `ValueError`.
- Ciphertext/tag alterado -> `ValueError` (tag GCM / padding / palabra de longitud).
- Prefijo / firma ausente o incorrecta -> `ValueError` / `False` segun la via (ver el test).
- `decode_public_servers()`: cuerpo no-JSON, JSON no-lista, lista vacia, HTML -> `DecodeError` `BAD_JSON`.

## 5. Limites y pendientes

- El vendedor vacio y luego borro minapronet.updater: hoy la app no recibe ningun MinaConfig de la red.
- El endpoint del sitio responde update_required para v88/v89 con cualquier HWID: hoy no entrega config.
- Sin .mina REAL exportado por la app; sin clave real de nube (27 caracteres); URL del canal de sincronizacion nativo no recuperada.
- DISTINTA de SLOW DNS (slowdns.minapronetvpn.com.eg, tanda 6): mismo desarrollador, distinto paquete y distinta app; el metodo k() se verifico de forma independiente en ESTE APK.
- ¿Cuando restaurara el vendedor el updater o servira el sitio 'config' (o una version nueva de la app)?
- URL del canal de sincronizacion nativo (nativeFetchServerConfig / nativeSetServerUrl en libminacore.so).
- El catalogo cableado en esta actualizacion es SOLO el de servidores publicos; MinaConfig sigue sin cablear.

## 6. Actualización 2026-11-17 — servidores públicos cableados

- Re-corrida en vivo `MinaProNet.py --public-servers --json`: **205 entradas, 205 online, 31 países**
  (153 ss, 29 trojan, 17 vless, 6 vmess); cuerpo crudo 137266 B, SHA-256
  `22740dfedd3a259848960040e6f09538b4e69b6f755cc65ae2ea083da3365793`.
- Comparación contra `~/workspace/catalogs/minapronet/live.json`
  (SHA-256 `3af7ff938a83192bc2d7d78399a0c1cee7d272eaaedc4eda11dcb4c6b3eec1e4`):
  **lista de servidores idéntica (205/205) y resumen idéntico** (entries/online/countries/protocols).
- Adaptador nuevo `decode_public_servers()` en `MinaProNet.py` (puro, sin red):
  verificado contra el cuerpo crudo en vivo — mismo resultado que `--public-servers`,
  sin `url` ni `bytes` en el resultado (regla del catálogo). Negativas: 4/4 `BAD_JSON`.
- Simulación del camino supplied completo (inventario actualizado + rama nueva en
  `supplied_bridge.py` `decode_one()` + módulo del staging, sin tocar el repo):
  `supplied_bridge.catalog("minapronet-vpn", raw)` devuelve
  `{entries, online, countries, protocols, servers}` con servidores y resumen
  idénticos a `live.json`.
- MinaConfig re-verificado SIN datos: updater HTTP 404, sitio `update_required` para
  las versiones 88–100. No se cablea. Flujo de nube por clave de 27 caracteres
  intacto (sin cambios de comportamiento; solo se añaden los helpers
  `parse_cloud_key()`/`format_cloud_key()` ya verificados en el self-test).
- Self-tests del staging: `MinaProNet.py --self-test` 22 líneas OK (21 pruebas + `all_ok`),
  `MinaProNet_archivos.py --self-test` 13 líneas OK (12 pruebas + `all_ok`), exit 0.
