# Validación `.hexcm`

## Corpus público sintético

```bash
python tests/golden/hexcm_reference.py
python -m unittest discover -s tests -p 'test_hex_tunnel.py' -v
python -m unittest discover -s tests -p 'test_cloud_c8_vpn_registry.py' -v
python scripts/cloud_formats_catalog.py
cd cloud/web
node --test tests/file-formats.test.mjs tests/server-vpn-catalog.test.mjs tests/server-vpn-version-sync.test.mjs
```

El productor requiere JDK 17+ y usa PBKDF2/AES-GCM/ChaCha20-Poly1305/SHA-256 de
JCA, sin importar el lector Python. Los 12 documentos válidos abarcan sobres
simples y dobles para seis casos: abierto, bloqueado, ID, compañía, ID/compañía
e inicio por ID. Se comparan documentos completos, incluidos campos desconocidos,
Unicode, arrays, nulos y metadatos; no solo cadenas seleccionadas.

Los diez casos inválidos incluyen seis tags interiores corruptos, firma
incorrecta, propiedades duplicadas, número no finito y versión no soportada.
Se verifican además tag exterior, truncamiento, tipo/tamaño de entrada, Base64
con saltos de línea, CLI fuera del checkout, stdout sin contenido parcial,
subproceso Cloud, rechazo de credenciales innecesarias y detección del bot.

El test del endpoint comprueba que un cliente con catálogo 60 recibe la entrada
`.hexcm` con capacidad Cloud y sin credenciales. Se conserva la sincronización
monotónica de versiones, los switches y el roster de proveedores.

## Muestras reales privadas

Dos originales con `blocked` false/true y cuatro muestras adicionales aportadas
por el propietario: ID, compañía, ID/compañía e inicio por ID. Los seis casos
simples AES-GCM conservaron 26 campos de servidor y firma válida. Se contrastaron
íntegros con JCA; los cuatro casos adicionales se probaron también por el
subproceso del motor Cloud integrado. Los originales no se modificaron.

Los documentos y sus valores privados permanecen fuera de Git y de CI.
El caso doble está verificado con vectores independientes; no se dispone de una
exportación real de esa variante. La importación Android de copias recifradas,
la conexión VPN y el despliegue en VPS no forman parte de las comprobaciones
realizadas aquí. `compatibleExportCertified` permanece en false.
