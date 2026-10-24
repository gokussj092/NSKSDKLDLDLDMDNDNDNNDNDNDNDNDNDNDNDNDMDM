# Validación de TunelGuard VPN 12.8 (128)

Fecha del lote: **2026-10-21**, zona America/Tijuana. APK base SHA-256:
`cf9f74da2b59f934ec3f8725092b87556eb10c636660888aa6a7117e65d0f7b8`.
Biblioteca ARM64 analizada, SHA-256:
`24707768a3e709acc09afcaead17401ac6d535c718bdedafb326644c7ecac354`.

## Evidencia y alcance

- Manifest: `tunnel.guard.vpn`, versión 12.8/128, importación `.tgv`, actividad
  `ExportActivity`. Métodos Java y registros JNI inspeccionados en build 128.
- Strings `lg3/kg3` recuperados ejecutando Java Random y comprobados además
  sobre los payloads DEX. Los parámetros no proceden de perfiles descargados.
- Función ARM64 de clave del catálogo `0xdae20` ejecutada completa: resultado
  igual a la constante del lector. El tag del catálogo inicial valida clave,
  AAD, nonce y sobre, y la implementación JCA independiente devuelve el mismo
  JSON entero. Copia inicial: **1 servidor, 1 ajuste, versión 0.1**, diez campos
  transformados no vacíos; todos los vacíos, tipos y metadatos también coinciden.
- `nDecryptUserConfig:0xdfbac` ejecuta el AES-CBC ARM64 real para textos de
  1, 15, 16, 17, 31, 32 y 257 bytes, más un `.tgv` sintético completo producido
  por el JDK, incluyendo texto no latino/emojis. Solo se modelan JNI strings,
  almacenamiento de strings C++, libc y TLS; el AES nativo no se sustituye.
- Oracle público `tests/golden/tunelguard_oracle.java`: JCA GCM/CBC, XOR por
  unidades UTF-16, Android Base64 con LF y Modified UTF-8 de DataOutputStream.
  Los vectores públicos son únicamente sintéticos: todos los 32 campos de
  servidor, ocho de ajustes, 16 de perfil, metadatos, servidores interiores,
  campos desconocidos y ambas variantes de mensaje.
- Ruta externa original: **HTTP 404**, 14 bytes, sin redirección, por Python
  HTTPS. Archivo y Contents API de GitHub confirman 404. Se obtuvo autorización
  expresa para la consulta; no falta permiso, falta un catálogo válido en origen.
  No se anuncian recuentos remotos ni se inventa una URL sustituta.
- Prueba local autenticada: solicitud de archivo → gateway → worker HTTP privado
  real → proceso aislado → JSON completo igual al JDK, `isPartial:false`.
  La copia sintética de catálogo también pasa por HTTP privado sin cambios.
  El broker público devuelve `REMOTE_NOT_CONFIGURED` para este proveedor y no
  realiza descargas o llamadas al worker, coherente con su ficha desactivada.

## Pruebas reproducibles

Desde la raíz y con dependencias en el mismo entorno que ejecuta los hijos:

```bash
PYTHONPATH=cloud/workers/python:. python -m unittest tests.test_tunelguard tests.test_http_wakko tests.test_http_socketclay tests.test_http_fenixvpn tests.test_http_jireh tests.test_cloud_c8_android_server_vpn -v
PYTHONPATH=cloud/workers/python:. python -m unittest tests.test_cloud_c8_vpn_registry tests.test_cloud_c8_worker_integration tests.test_cloud_c8_android_input_routes tests.test_austroplus_vpn tests.test_trv_tunnel tests.test_four_u_tunnel_lite tests.test_ac_tunnel_vpn -v
python scripts/cloud_c0_inventory.py --check
cd cloud/web
npm test
```

Resultado: **140 pruebas Python** (78 + 62, incluidas 12 de TunelGuard) y
**163 pruebas Node**, todas aprobadas localmente; matriz C0 sin cambios y
`git diff --check` correcto. Se añadieron casos `.TGV` al test instrumentado
Android, pero no se ejecutó emulador/compilación Android en esta validación.
No se presupone el resultado de GitHub Actions.

Cobertura: JSON íntegro, límites y profundidad, campos nulos/vacíos, Unicode y
Modified UTF-8, tipos/metadata, versiones, tags/cabecera/nonce/ciphertext GCM,
padding/estructura CBC, Base64 interior corrupto, entrada ambigua/no finita,
CLI desde fuera del repositorio, worker aislado y fuente fija 404/HTML/redirects/
compresión. La regresión distingue las 240 rutas C0 y 247 rutas Cloud efectivas;
no se altera la selección de los formatos históricos.

## Entrega y pendientes

- Nueva carpeta `decoders/Python/apps/TunelGuard_VPN/`: lectores separados,
  codec, mapa de campos, requisitos, icono original y PNG sin pérdida,
  manifiesto, README y este documento.
- Backend: `engine.py` registra `.tgv` y el ID de catálogo offline;
  `catalog_vpn_bridge.py` fija el módulo. El broker no habilita el origen 404.
- `server-vpn-catalog.mjs`: ficha desactivada, icono y mínimo 17. Las pruebas
  garantizan que una disponibilidad forzada no habilita su descarga.
- Cliente: `CloudFileFormats.kt` añade únicamente detección Cloud `.tgv`;
  prueba de ruta instrumentada actualizada, diseño y código de cifrado intactos.
- `tests/test_tunelguard.py`, oracle/vectores, pruebas de registro, inventario,
  catálogo e iconos; CI C2 incluye el nuevo lector.
- Registro `docs/cloud/NUEVAS_INTEGRACIONES_VPN.md` distingue `.tgv` terminado
  del catálogo remoto pendiente. No se generan anuncios C11.

No se aportó exportación `.tgv` real independiente, ni se certificó writer,
importación Android o roundtrip. La ejecución de funciones nativas aisladas no
se presenta como ejecución de toda la aplicación. Hace falta que la fuente
oficial vuelva a devolver un catálogo autenticado para verificar remoto y
habilitar el broker; conservar la ficha desactivada hasta entonces. Requiere
actualización del backend y cliente para reconocer `.tgv`; sin despliegue,
fusión ni publicación de APK automáticos.
