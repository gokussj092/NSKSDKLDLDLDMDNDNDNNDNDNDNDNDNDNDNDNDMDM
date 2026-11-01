# Netcol VPN 14.2: evidencia de comprobación

Análisis del 2026-10-31. Goku, rama `fix/http-jireh-current-method`, sobre Wolf
`22f8da94`. Revisión del catálogo **59 conservada por petición del propietario**.

## Entradas e iconos

| Entrada | Bytes | SHA-256 |
| --- | ---: | --- |
| XAPK 14.2 (142) | 55901014 | `f5ff0468b89c847916b5164f665e406afe2cfb3861e994c228df385f3bd9007a` |
| Base APK | 22102188 | `1f449d216199f5f6ebc55087e6e8cbe8248aafa3fe158e898d9abbc17d68dd7a` |
| Launcher WebP original | 12088 | `0c5bfb9bfa5250413d300133b1339b4a2ff80ad7716664b3573d3bd07ba12f28` |
| PNG con los mismos píxeles | 19306 | `1cf1a5995d31294a39ffcc03630af88bfcee91577ba061852cc82eb7da9d0b39` |

Firma SHA-256 `deee85eccbd9a67c1ed7dc6bf74f00bd5eef7432f88637b789919f2f7dd94f92`.
La firma SHA-1 coincide con la publicada para este paquete:
`782749d51dc4c29b560d51b032b98490c287f988`.
Descarga efectiva: `https://d.apkpure.net/b/XAPK/com.netcol.vpn?version=latest`;
la variante `/b/APK/` devolvió el mismo XAPK. El host .com respondió 403.

## Repetir sin depender del entorno temporal

Desde la raíz, con JDK, PyCryptodome y las dependencias de análisis para el APK:

```bash
python scripts/apk_analysis/netcol_source.py /ruta/com.netcol.vpn.apk --fetch
python scripts/apk_analysis/netcol_verify.py /ruta/config-cifrado.json --worker
python scripts/apk_analysis/netcol_verify.py /ruta/remoto-cifrado.json --worker
python -m unittest tests.test_netcol_vpn tests.test_wolf_custom_vpn tests.test_http_jireh tests.test_jyfast_vpn_ultra tests.test_cloud_c8_vpn_registry tests.test_cloud_c8_worker_integration.C8WorkerIntegrationTests.test_unchanged_prior_inventory_and_explicit_new_file_routes
python scripts/cloud_formats_catalog.py
```

`netcol_source.py` fija APK/firma, lee metadatos públicos SDK y opcionalmente
consulta Remote Config con un identificador de prueba generado. Muestra solo
identidad, fuente y hashes; no API keys. La respuesta observada tuvo SHA-256
`81f86f766664678297270f1e74eb29963c786d89b8187b4d66277322cd942f14`
y `NEW_URL_UPDATE` coincidió con la URL fijada en el lector. No ejecuta
`URL_CASUP` ni otras entradas de esa respuesta; son datos externos.

`netcol_verify.py` abre el sobre y los siete campos con **JCA** y compara todo
el JSON con Python y, con `--worker`, el subproceso aislado real. No imprime ni
guarda configuraciones. `tests/golden/netcol_oracle.java` deriva su propia
clave AES desde los bytes y usa Blowfish JCA; los fixtures se generaron con
ese programa, no con el descifrador que prueban.

Las **9 pruebas nuevas Python** cubren ambas claves Blowfish, la derivación
hexadecimal, tipos mixtos, ServerPass sin transformar, ciphertext desconocido,
vacíos, padding/símbolos/JSON incorrectos, duplicados, NaN, profundidad y límites,
CLI fuera del checkout, errores sin datos, fuente fija e iconos. Con regresiones
se aprobaron **43 Python**, sin skips.

Node: **146 pruebas dirigidas aprobadas** (79 del grupo de broker/catálogo y
67 regresiones adicionales), sin skips. Incluyen seis pruebas nuevas Netcol:
DNS privado, redirecciones al enlace antiguo o externo, metadata/icono con
revisión 59, control persistente que conserva otros estados, envío de todos
los bytes al worker autenticado y rechazo de resultados parciales/incoherentes.
No se lanzó GitHub Actions ni la suite completa.

## Muestras reales, fuera de Git

| Muestra | Versión | Servidores | Campos cifrados | Bytes cifrados | SHA-256 |
| --- | --- | ---: | ---: | ---: | --- |
| Cada asset incluido (ambos iguales) | 0 | 2 | 14 | 9096 | `f20cbbce7cca17771945fad909cef45f2901386ab38543c4af454f630edf448b` |
| Remoto activo | 162 | 172 | 1204 | 1076496 | `6f847dfe13c1f95a3c9d0646c8f08352c25ca1d5b57b3c84950794cf1d856256` |

Salida real remota: **147817 bytes** de `rawText`, **280521 bytes** de respuesta
interna, igualdad JSON completa y `isPartial=false`. El CLI final descargó
162/172 y coincidió íntegramente con el worker; esa respuesta pasó también
`fetchWorker` con HTTP 200 mediante transporte interno simulado.

El fallback antiguo `/jdavidag/update/main/Config` respondió HTTP 200 con solo
un salto de línea (SHA-256
`01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b`).
No se considera un catálogo válido ni se usa en el broker.

Alcance pendiente: ejecución Android/conexión VPN, transporte Node real hacia
el proveedor y despliegue VPS. No se identificó un formato propio de archivo
exportado; no se añade lector ni extensión. CBC no tiene MAC nativo; las
pruebas de padding/JSON no certifican integridad criptográfica del formato.
