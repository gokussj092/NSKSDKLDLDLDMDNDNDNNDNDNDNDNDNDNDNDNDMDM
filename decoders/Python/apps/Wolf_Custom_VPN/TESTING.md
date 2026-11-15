# Actualización 2026-11-09

La evidencia vigente está en [RESULTS.md](../../../../analysis/core.vpn3jx.xtreme/16/RESULTS.md) y su [REPRODUCE.md](../../../../analysis/core.vpn3jx.xtreme/16/REPRODUCE.md). El informe histórico siguiente se conserva y no describe el build actual.

# Comprobaciones: Wolf Custom VPN build 13

Fecha de análisis: 2026-10-31. Cuenta Goku, rama
`fix/http-jireh-current-method`. Sin merge, despliegue ni GitHub Actions nuevos.

## Procedencia y hashes

| Entrada | Bytes | SHA-256 |
| --- | ---: | --- |
| XAPK v2.8.1.2 (13) | 59349423 | `d82f07a06fb9b0e1e42e1b0010601c65697bd595057b6a323db5eec5ad59a58d` |
| Base APK | 30511568 | `7511b35542ba6ab0f75bfc01808038d53d007a90cd5567c5133e748ae7c83660` |
| libgojni.so ARM64 | 30686992 | `909d2a470dee286d4b9fdcf425b2972966f7ba4be54654036ff493408862ca2d` |
| libgoinjector.so ARM64 | 5318448 | `9bd2ff407ee3371894239826a5677749129453b4fdadf7bdce10decdccfcd5d5` |
| Launcher WebP original | 30888 | `f17c3fb34f49745ec323cd00277fd1b07efd34891801a4ebd932ff083a6fc997` |
| PNG con los mismos píxeles | 43997 | `4e403e8f44b840eadb67af9062d0b0455ffc88c37706bee4b949ca94513fa1c0` |

Certificado firmante SHA-256:
`bd6515d3f58f73aa59ae99ae1d2aff74c4e2665c3bd677fbefea77222e88fc6b`.
Fuente descargada: `https://d.apkpure.com/b/XAPK/core.vpn3jx.xtreme?version=latest`.
Confirmar versión por el manifiesto binario; la página web del espejo contenía
metadatos obsoletos.

## Reproducción

Desde la raíz del checkout, con JDK y dependencias instaladas:

```bash
python scripts/apk_analysis/wolf_native_constants.py /ruta/lib/arm64-v8a
python scripts/apk_analysis/wolf_verify.py /ruta/asset-cifrado.json --worker
python scripts/apk_analysis/wolf_verify.py /ruta/remoto-cifrado.txt --worker
python -m unittest tests.test_wolf_custom_vpn tests.test_http_jireh tests.test_jyfast_vpn_ultra tests.test_cloud_c8_vpn_registry tests.test_cloud_c8_worker_integration.C8WorkerIntegrationTests.test_unchanged_prior_inventory_and_explicit_new_file_routes
python scripts/cloud_formats_catalog.py
```

El primer script fija los hashes de ambos nativos y resuelve los nombres Go,
las entradas de función, sus llamadas Base64/AES/GCM y los 32 bytes usados
directamente como clave. El segundo abre el sobre con JCA y compara el JSON
entero: detecta todos los valores que autentican con ambas claves, los descifra
con Java y exige igualdad con el lector y, opcionalmente, el worker real aislado.
Solo imprime recuentos, tamaños y hashes. No guarda configuraciones.

Los datos de `tests/golden/wolf_vectors.json` se cifraron con
`tests/golden/wolf_oracle.java`, usando nonces sintéticos deterministas. Cubren
las dos claves, vacíos cifrados, Unicode, listas, booleanos, puertos, estructuras
anidadas y claves desconocidas. Las pruebas rechazan tags alterados, duplicados,
NaN, profundidad/salida excesiva, perfil con esquema incorrecto y entradas que
deban fallar sin imprimirlas. El fallback histórico se probó con Argon2/GCM
real y conserva `.wolftunnel` y los 240/254 inventarios anteriores.

Desde `cloud/web` se ejecutaron los 17 archivos dirigidos a Wolf, JyFast, Jireh,
Focus, provider/catalog/version-sync, file-formats, ANY/Speicers, MTM,
TunnelDOOM, BD NET, APNA, Aura, MNR, text-format-catalog y http-custom-online.
Resultado: **140 Node aprobadas**, sin skips. Wolf comprueba URL fija, todos
los bytes al worker, respuesta completa, icono, control persistente, rechazo
de DNS privado, redirecciones, tipos incorrectos y resultados parciales. La
prueba de caché de revisión 57 añadida en otra sesión se conservó y se añadió
la de revisión 58 para Wolf. **34 Python aprobadas**, sin skips.

## Muestras reales fuera de Git

| Captura | SHA-256 de entrada cifrada | Bytes de entrada | Campos descifrados |
| --- | --- | ---: | ---: |
| Asset 1.01, 1 servidor / 3 redes | `a11fb0d40b622ccbdab8ec2177e88a482c6ecb17b0e16e228bdf9f37fd585a71` | 7984 | 31 |
| Remoto 6.44, 164 / 2014 | `13b367abcf2ca12a623df5f1c0036454d928be2f7bbd66cf4786b558eb8d5670` | 4104780 | 13260 |
| Remoto 6.45, 164 / 2015 | `6fe7c7530f973578070ca318514efdd2db261f5f1ffc4c6b8a1a7044fc7d4e94` | 4105536 | 13267 |

Todos los documentos completos coinciden con JCA/Python/worker. El 6.45 produce
2656081 bytes de `rawText`, 5175411 bytes de respuesta interna y
`isPartial=false`. Ambos tamaños caben en los límites actuales. La descarga
actual se comprobó por el CLI Python real; el JSON completo del worker 6.45
también pasó `fetchWorker` (HTTP 200) usando transporte interno simulado.
Los cambios 6.44→6.45 son del
proveedor. Los scripts no fijan los recuentos ni mezclan catálogos.

Límites de comprobación: no se ejecutó código Go completo ni la app original
en Android; los offsets y constantes se comprobaron por lectura y desensamblado.
No se obtuvo `.wolf` exportado desde un teléfono; solo vectores sintéticos y
ruta DEX de exportación. No se certifican exportador, conexión VPN, transporte
Node real hacia el proveedor ni despliegue VPS. No se ejecutó la suite completa.
