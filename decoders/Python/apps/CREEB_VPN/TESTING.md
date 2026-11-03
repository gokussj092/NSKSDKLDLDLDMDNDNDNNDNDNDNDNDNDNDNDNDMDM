# Revisión2026-11-01

26 pruebas Python aprobadas,0 skips:

```sh
python -m unittest tests.test_creeb_remote_request tests.test_creeb_vpn \
  tests.test_creeb_injector tests.test_cloud_c8_vpn_registry -v
```

Siete nuevas sobre preflight/digest/caché/flag del servidor, solicitud privada
sin cambiar token/nonce, tipo de petición/cabeceras, diagnóstico offline,
rechazo total de HTML y JSON completo/0600 con transportes simulados.
Los tokens de fixtures son sintéticos, nunca se envían al proveedor.
No prueban una atestación real.26=19 anteriores+7 nuevas.

`creeb_vpn_verify.py --catalog /privado/data.creeb --worker`:6 documentos
enteros iguales a JDK/CLI/worker, de los que5 son sintéticos y1 incluido real
1.0.0/1 servidor/1 ajuste. Hashes del original iguales a los ya documentados.
Dalvik de mv0.doInBackground182, onPostExecute245 y lv0.doInBackground185
contrastó la secuencia de red, más nonce/reintento. JADX parcial52 errores.

Prueba real del script actualizado: GET200 HTML195→POST sin token405 HTML163,
exit1/catalogValid:false y ningún JSON remoto. No se obtuvo token válido de
Play Integrity, ni hay Android conectado. La ruta completa con ese token
fresco sigue sin probarse. No se anuncia remoto operativo o integración cerrada.
Los hashes y diagnóstico de fallo no se atribuyen a rechazo de Integrity.

Sin cambios de broker/icono/UI/contadores, suites Node no repetidas porque no
se modifica web. No se ejecutó CI manual, build Android o despliegue.

---

# Validación — 2026-10-23

- **19 pruebas Python aprobadas**: 9 de CREEB VPN, 9 regresiones CREEB INJECTOR
  y 1 registro C8. C0 conserva 240 rutas; C8 sigue 250 (se sustituye `.crev`,
  no se añade una extensión). `.cer/.cerv` y `.creeb` mantienen motores distintos.
- **50 pruebas Node aprobadas**: catálogo, monotonía/persistencia de versión,
  watch y controles. Server VPN mínimo **36**, **38 tarjetas**. La ficha CREEB
  VPN sigue desactivada incluso con disponibilidad global; switches conservados.
- JDK independiente: **24 vectores de primitiva**, ambas claves y límites de
  alineación/UTF-8; **5 documentos sintéticos** con arrays múltiples, claves
  distintas, todos los campos, vacíos/null, metadata desconocida y bloqueos.
- **Catálogo real incluido**, versión 1.0.0, 1 servidor / 1 ajuste: igualdad de
  todo el JSON con JDK, CLI y worker aislado. Total **6 documentos iguales**
  frente a JDK, **6 CLI**, **6 worker**. Rutas HTTP internas de archivo y catálogo
  conservan el JSON completo y `isPartial:false` en pruebas sintéticas.
- Casos negativos: clave contextual incorrecta, Base64/truncamiento/framing,
  UTF-8 inválido, JSON duplicado/no finito/surrogates, HTML, tipos incompatibles,
  entrada >8 MiB y campo interno corrupto. Se rechaza el documento completo.
- CLI desde otro directorio y stdin; contraseña/ID externos no se necesitan.
- Icono verificado visualmente; PNG renderizado desde todas las rutas originales
  y copias con hash idéntico. Cairo puede diferir en antialiasing de Android.

Comandos desde el checkout (Python con PyCryptodome, JDK 17 y Node 22+):

```bash
python -m unittest tests.test_creeb_vpn tests.test_creeb_injector tests.test_cloud_c8_vpn_registry
python scripts/apk_analysis/creeb_vpn_verify.py --catalog /ruta/data.creeb --worker
cd cloud/web
node --test tests/server-vpn-catalog.test.mjs tests/server-vpn-version-sync.test.mjs tests/c10-catalog-push.test.mjs tests/c12-provider-controls.test.mjs
```

`tests/golden/creeb_vpn_generate.py` regenera fixtures sin importar el codec.
`creeb_vpn_verify.py --file /ruta/real.crev --worker` añade una exportación real
sin imprimir sus valores. **No se recibió ningún `.crev` real**: las pruebas de
archivos son sintéticas, basadas en el exportador estático. No se anuncia paridad
con una importación Android real ni catálogo remoto funcional. GET/POST del
actualizador devolvieron HTML; falta una respuesta oficial válida. Sin suite
global, despliegue, recompilación de APK o publicación C11.
