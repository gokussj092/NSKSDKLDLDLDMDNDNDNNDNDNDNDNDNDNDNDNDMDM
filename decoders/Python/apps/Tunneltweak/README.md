# Tunneltweak — 6.2.3 / build53

Expediente, herramientas y dependencias:
[analysis/com.tunneltweak.loyalteams/53](../../../../analysis/com.tunneltweak.loyalteams/53/ANALYSIS.md).

El servidor exige ahora x-app-version 53; la cabecera51 producía HTTP426.
Se verificó el build53 del APK y se actualizó el GET del broker y del lector
autónomo. El método criptográfico público sigue siendo PBKDF2-SHA256/10000 y
AES-GCM: no se reemplazó una primitiva que ya funcionaba.

El catálogo completo observado contiene 2 servidores y 68 configuraciones y
coincide con el oráculo Java/JCA reutilizado, Python y el worker. Se conservan
announcement, metadatos, campos desconocidos y tipos.

~~~bash
pip install -r requirements.txt
python server_catalog_decoder.py > catalogo_privado.json
python server_catalog_decoder.py copia_cifrada.txt > catalogo_privado.json
python file_decoder.py perfil.tut > perfil_privado.json
~~~

Se mantienen las variantes CBC, TTPBE1 con contraseña del usuario y XOR legado;
config_version6, límites, caducidad y HWID siguen siendo metadatos de las rutas
observadas. La opción --api-key-file del CLI acepta únicamente una clave propia
autorizada; no se usó ninguna suscripción privada para validar esta actualización.

El UUID Cloud y los perfiles siguen sus rutas anteriores. No se certifican
exportaciones reales nuevas de teléfono, acceso premium, ejecución Android ni
conexión VPN. El servidor se actualiza por separado; no hace falta compilar
otra APK de SP-DECODE.
