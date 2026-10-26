# Validación de ANY VPN

Comparación de JSON entero con una implementación independiente JDK y el
worker aislado real, sin valores de catálogos privados guardados en Git.

| Documento real | Versión | Servidores | Redes | Campos conocidos, incluidos vacíos |
|---|---|---:|---:|---:|
| Constante cifrada del DEX | 1.1 | 12 | 46 | 342 |
| GET oficial con User-Agent del APK | 5.84 | 13 | 91 | 535 |

Los dos documentos, todas sus listas, campos y metadatos son iguales al JDK.
Dos perfiles sintéticos adicionales, red sola y servidor/red, también coinciden
completos con JDK y decode_file('dtk'). La salida convierte las cadenas JSON de
las secciones del contenedor en objetos, conservando los campos adicionales.

```bash
python -m unittest tests.test_any_vpn tests.test_speicers_pro tests.test_cloud_c8_vpn_registry -v
python scripts/apk_analysis/any_vpn_verify.py /ruta/embedded.enc /ruta/remoto.enc
python scripts/apk_analysis/any_vpn_verify.py --file /ruta/perfil.dtk
cd cloud/web
node --test tests/server-vpn-any-speicers.test.mjs tests/server-vpn-catalog.test.mjs tests/server-vpn-provider.test.mjs tests/server-vpn-version-sync.test.mjs tests/file-formats.test.mjs
```

13 tests nuevos de ANY: documentos completos, certificados/flags/extra,
secciones individuales, JSON interno duplicado, estructura/límites/UTF-8,
padding, errores sin contenido privado, entrypoints offline, GET/agente fijo,
rechazo de redirecciones y CLI autónoma 0600 sin sobrescritura. La referencia
Java usa MessageDigest y Cipher JDK; no ejecuta clases del APK.

Con Speicers y registro C8: **28 tests Python aprobados**. Las suites Node de
catálogo, proveedores, sincronización y formatos: **60 aprobados**. Verifican
41 / 42 fichas, iconos exactos, ambas tarjetas y switches individuales que no
reinician proveedores deshabilitados, DNS/IP/TLS y redirecciones bloqueadas.

Además, 85 regresiones Python aprobadas de inventario/worker C8, MM, Tx,
4U, AC, 1FTunnel, TRV y AustroPlus: **113 pruebas Python en total**. Los tests
con conteos fijos se actualizaron a C8 251 / 21 entradas overlay, preservando
C0 240. El generador de formatos públicos y validate_project.py coinciden.

La CLI copiada fuera del checkout se probó también con la descarga real. No se
ejecutó en Termux/Android: usa Python y PyCryptodome sin APIs de escritorio o
privilegios. Pendientes: .dtk real e interfaz de exportación/importación Android.
CBC no aporta MAC; los tests de corrupción no son una prueba de autenticidad.
