# RESULTS — MinaProNet 88.0.0 (versionCode 88)

Fecha de las pruebas: 2026-11-14/15. Entorno: Python 3.12.3 del sistema, solo stdlib, sin red
para los tests de este expediente. Las pruebas en vivo citadas se hicieron 2026-11-14/15 con
los scripts operativos (ver `~/workspace/catalogs/minapronet/` y NOTES.md).

## 1. Estado probado por via

| Via | Estado | Evidencia |
|---|---|---|
| catalog | FAILED | Updater en vivo VACIADO por el vendedor (HTTP 200, 14 B, 'hello world..' el 2026-11-14; luego HTTP 404, archivo borrado; jsDelivr aun sirve copia en cache). Respaldo de emergencia 404. El endpoint del sitio responde update_required para v88/v89: hoy NO entrega config. El METODO esta verificado por control: k() abre en vivo slowdns_config.json (v4, 7 servidores, 54 redes). Servidores publicos (segunda fuente, JSON plano): 213 entradas / 33 paises (2026-11-14) -> 234 entradas / 35 paises (2026-11-15). |
| files | VERIFIED_SYNTHETIC | .mina (Manager.exportTest/importTest): muestra SINTETICA muestra.mina (3046 B) sellada y reabierta con JSON identico; sin .mina REAL exportado por la app. 68 campos; caducidad por t (ms); pw y HWID son campos del JSON, no parte de la clave AES. |
| text | NOT_APPLICABLE | Sin esquema propio; enlaces V2Ray estandar pegados en la interfaz; Manager.dcx/dpt aplica ROT-1 internamente. Nada nuevo para SP-DECODE. |
| export | PENDING | Nube por clave: Firebase Storage, <clave de 27 caracteres>.mina. Validado en vivo con clave inventada -> CLOUD_KEY_NOT_FOUND (HTTP 404); falta una clave real. Sincronizacion servidor->app (nativeFetchServerConfig): URL del canal no recuperada. |

## 2. Verificacion en vivo (oraculo independiente)

Updater en vivo vacio (200, 14 B) luego 404; sitio update_required (v88/v89); control k() sobre slowdns_config.json en vivo (v4, 7/54); servidores publicos 213/33 paises (11-14) -> 234/35 (11-15).

Self-tests de los scripts operativos: Catalogo 16/16 (8 viejas + 8 nuevas del sitio), archivos 7/7 (scripts operativos, 2026-11-15).

## 3. Tests de este expediente (sinteticos, sin red)

- `python3 tests/test_method.py` (unittest): **8 tests, OK** (exit 0).
- `python3 tools/verify.py`: **OK** (exit 0).
- Fixtures en `tests/fixtures/`: vectores SINTETICOS generados con claves TEST-ONLY
  (`bytes(range(...))`); no contienen material real, servidores reales con claves ni perfiles reales.
- pytest NO esta instalado en este entorno; los tests son `unittest` (stdlib) y compatibles
  en forma con pytest cuando este instalado.

Clasificacion: lo anterior es **VERIFIED_SYNTHETIC** para la logica del formato.
Lo en vivo es **VERIFIED_REAL** solo donde la via lo indica arriba; donde la via es
PENDING/FAILED, nada sintetico la convierte en verificada.

## 4. Pruebas negativas (incluidas en tests/test_method.py)

- Entrada truncada -> `ValueError`.
- Base64 invalido / HTML inesperado -> `ValueError`.
- Ciphertext/tag alterado -> `ValueError` (tag GCM / padding / palabra de longitud).
- Prefijo / firma ausente o incorrecta -> `ValueError` / `False` segun la via (ver el test).

## 5. Limites y pendientes

- El vendedor vacio y luego borro minapronet.updater: hoy la app no recibe ningun MinaConfig de la red.
- El endpoint del sitio responde update_required para v88/v89 con cualquier HWID: hoy no entrega config.
- Sin .mina REAL exportado por la app; sin clave real de nube (27 caracteres); URL del canal de sincronizacion nativo no recuperada.
- DISTINTA de SLOW DNS (slowdns.minapronetvpn.com.eg, tanda 6): mismo desarrollador, distinto paquete y distinta app; el metodo k() se verifico de forma independiente en ESTE APK.
- ¿Cuando restaurara el vendedor el updater o servira el sitio 'config' (o una version nueva de la app)?
- URL del canal de sincronizacion nativo (nativeFetchServerConfig / nativeSetServerUrl en libminacore.so).
