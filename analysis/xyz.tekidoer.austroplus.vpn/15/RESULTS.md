# Resultados reales y pruebas — build15

Estado catálogo: VERIFIED_REAL. GET actual HTTP200 /82433bytes, v0.8, 5 servidores y174 ajustes; 361 campos protegidos comparados. Incluido: 2320bytes, v0.0, 1 servidor y1 ajuste, 18 campos comparados. Ambos JSON completos coinciden entre Java independiente, Python y worker aislado; rawText y structuredJson íntegros e isPartial=false.

Salida remota: 59729bytes. SHA-256 canónico del JSON claro: 6e6fb6580e119d8550dd72402bdc288205cd7d0155da8c203a3363697805185d. El contenido real no se publica. generated/catalog-proof.json y embedded-proof.json contienen huellas y conteos.

19 pruebas AustroPlus correctas (14 anteriores y5 nuevas). Con CATNET, Tunneltweak e historial automático: 61 Python y77 Node correctas. Incluyen igualdad completa, campos desconocidos/tipos, dos esquemas, worker real, errores de campos/nombres, política remota, límites y recuperación persistente. Fixture nuevo sintético SHA-256: 196bb13a1defa236189e08723a25a043d5fa9cbe3554eecb3286cf648de086c4. Los fixtures no prueban una exportación real de teléfono.

Se ejecutaron Python3.12.14, Androguard4.1.3, PyCryptodome3.23.0, JADX1.5.6 completo, OpenJDK21.0.13 y Node24.22.1. No se instalaron paquetes nuevos: se reutilizó el entorno aislado; las dependencias instaladas y las no ejecutadas están diferenciadas en el lock. CI utiliza Node22.

Fallos preservados: primer inspector rechazó el esquema nuevo; primer lanzamiento concurrente Java no produjo el recuento esperado y fue rechazado; comprobaciones secuenciales completas correctas. JADX conserva errores ajenos al camino revisado. La firma criptográfica completa APK, exportaciones build15 reales, Android y VPN no se certifican. No se fusionó main ni se desplegó VPS ni se compiló APK.

Auditoría actual: A0 sin bloqueos; P06 PASS_WITH_UNRESOLVED,7 métodos modificados,90 fuentes alcanzadas,14 expedientes y46 consumidores sin resolución estática. Ocho expedientes consumidores incorporan revisión documental. Las incertidumbres no se consideran aprobadas. Build web correcto; la ruta compilada respondió503 esperado con servicio desactivado, sin error de carga del módulo.
