# Validación de HTTP Wakko 4.9

Fecha de validación del lote: 2026-10-21. Paquete `com.wakko.http`, build 40.
APK base SHA-256:
`0cea08de7ccef4d4c26a33be1fd7cfa1354c9f5051d81ce5e9f9eaf9c5ad971f`.

## Evidencia independiente

- Manifest, DEX, consumidores `C6851`, `C6863`, recursos y ambas rutas de
  actualización inspeccionados. Sin formato de perfil exportado identificado.
- `libcrypto.so:0x6e1fc` ejecutado para `1`, `40`, `2026.10.21`, `synthetic-v2`:
  SHA/KDF ARM64 reales; operaciones C++ de strings y callback Java ChaCha
  modelados. Los cuatro resultados coinciden con `field_key`. No se presenta
  como ejecución completa de la app ni Android.
- Configuración `WKCFGSTART` autenticada con tag ChaCha válido. Los parámetros
  de compilación coinciden con las primitivas reutilizadas de SocketClay.
- `tests/golden/wakko_oracle.java` usa exclusivamente JCA/JDK, independiente
  del lector Python. Compara todos los campos y documentos, no muestras:

| Fuente | Version | Registros | Campos cifrados no vacíos | JSON completo |
| --- | --- | --- | --- | --- |
| APK config.png | 1 | 1 servidor | 7 | Igual |
| APK usr.png | 1 | 2 entradas de usuarios | 10 | Igual |
| Remoto servidores | 116 | 91 servidores | 725 | Igual |
| Remoto usuarios | 8 | 2 entradas de usuarios | 10 | Igual |

- Las fuentes originales con su redirección firmada y las directas HTTPS
  devuelven bytes idénticos: 170304 / 1792 bytes. Autorización externa expresa
  del usuario para ambas. No se consultaron conexiones VPN ni se utilizaron
  las cuentas del catálogo para iniciar sesiones.
- Incluye cuatro valores BHTTP no vacíos en dos servidores tipo 5. Sus slots
  no se sustituyen por los valores por defecto de la UI.
- La CLI real `--all` descargó ambas fuentes y coincide con los dos documentos
  del oracle. Flujo autenticado local: petición → broker con capturas reales
  de ambas fuentes fijas → worker HTTP privado real → proceso aislado → JSON
  completo. `isPartial:false` e igualdad total con el oracle.
- Node DNS devuelve `EAI_AGAIN` aquí. DNS/IP/TLS/redirecciones se prueban con
  transporte controlado; descargas externas reales por Python/HTTPS. La prueba
  local no acredita despliegue o conectividad externa de la VPS.

## Pruebas reproducibles

Con dependencias del repositorio instaladas en el entorno Python que usen los
procesos aislados y JDK disponible:

```bash
PYTHONPATH=cloud/workers/python:. python -m unittest tests.test_http_wakko tests.test_http_socketclay tests.test_http_fenixvpn tests.test_http_jireh tests.test_cloud_c8_android_server_vpn -v
python scripts/cloud_c0_inventory.py --check
cd cloud/web
npm test
```

Resultado local: **66 pruebas Python**, incluidas **16 de Wakko**, y **162
pruebas Node**, todas aprobadas. Inventario C0 intacto y `git diff --check` correcto.
No se presupone el resultado de la CI remota.

Los vectores públicos son sintéticos: cuatro versiones, 20 campos directos/
envueltos, rotación Java/UTF-16, todos los 29 campos de servidor, siete de
usuarios, cinco tipos de servidor y documentos con versiones independientes.
Las pruebas cubren tags alterados sin fallback CBC, cabecera/padding/versión,
JSON ambiguo/no finito/profundo, campos BHTTP corruptos/vacíos, metadatos
anidados, límites, bundle incompleto/corrupto, CLI fuera del repositorio,
worker aislado, descargas duales, controles administrativos, iconos y caché.
La suite SocketClay/Fenix/Jireh verifica los lectores compartidos anteriores.

## Archivos y rutas entregados

- `decoders/Python/apps/HTTP_Wakko/`: `codec.py`, `field_names.json`,
  `server_catalog_decoder.py`, `requirements.txt`, `manifest.json`, `README.md`,
  `TESTING.md`, `HTTP_Wakko.webp` original y `HTTP_Wakko.png` sin pérdida.
- `tests/golden/wakko_oracle.java`, `wakko_vectors.json` y
  `tests/test_http_wakko.py`; CI C2 incluye la nueva suite.
- Worker: `catalog_vpn_bridge.py`, allowlist de `engine.py`.
- Backend: `server-vpn-provider.mjs`, `server-vpn-gateway.mjs`, `c3-gateway.mjs`,
  `paired-vpn-catalogs.mjs` y wrapper compatible `socketclay-catalogs.mjs`.
- Catálogo/controles: `server-vpn-catalog.mjs`, `c12-provider-controls.mjs`,
  `public/server-vpn-icons/http-wakko.png` y pruebas correspondientes.
- `HTTP_SocketClay/codec.py` expone el recorrido compartido parametrizado por
  esquema; su ruta original conserva el mismo formato y resultado.
- Índice de apps y registro `docs/cloud/NUEVAS_INTEGRACIONES_VPN.md` actualizados.

No hay muestras privadas en Git. No se ejecutó Android ni se certificó writer,
importación/exportación de perfiles, despliegue, fusión o publicación de APK.
Los límites fallan explícitamente y no producen listas truncadas.
