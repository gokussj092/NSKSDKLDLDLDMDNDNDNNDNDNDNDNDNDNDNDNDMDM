# Ultra Tunnel — catálogo de servidores build59

Paquete `co.strongteam.ultra`, versión **v1.0.8.8/build59**.
Proveedor Cloud estable **ultra-tunnel**, integrado en código y pendiente
de desplegar. Descarga real **HTTP200**, catálogo **5.18**:
**47 servidores/917 redes/5034 campos protegidos**.
JSON completo igual a libsodium/JCA, CLI de descarga y worker aislado.

## Uso

Python3.10+, dependencias en requirements.txt. Desde la raíz:

```bash
python decoders/Python/apps/Ultra_Tunnel/server_catalog_decoder.py --download
python decoders/Python/apps/Ultra_Tunnel/server_catalog_decoder.py copia.enc
python decoders/Python/apps/Ultra_Tunnel/server_catalog_decoder.py --stdin < copia.enc
```

Sin argumentos también descarga. Los modos son excluyentes. stdout contiene
el JSON privado completo; conservarlo fuera de Git. Errores saneados en stderr,
exit1 y stdout vacío. No recibe URLs, claves de otros usuarios ni flags para
desactivar TLS. API offline: `run(data:bytes)->str`.

El GET usa la fuente y User-Agent originales. No necesita sesión, cookie,
API key privada, registro o renovación; CU no usa esas entradas.
El worker solo abre bytes entregados por el broker y no realiza la descarga.

Sobre remoto: letra en índice3, Base64, salt16/nonce12/tag16,
Argon2id3/8192/1/AES256-GCM/AAD=salt. EO/DO incluido y campos usan
la clave secundaria. Ambas constantes se reutilizan del perfil Ultra/Sandok
existente después de contrastarlas con el SO de build59.
Los campos conocidos se abren en sus contextos; todo el JSON restante se
conserva. Cualquier tag protegido inválido rechaza el documento completo.

No cambia las rutas históricas de archivos .ultra/.ulti/.ultratunnel/.ut
ni crea un nuevo escritor/exportador. No se certificó una exportación
de archivo real de este build como parte de la descarga de catálogo.

[Pruebas](TESTING.md), [manifest](manifest.json) y
[handoff con hashes, origen y límites](../../../../docs/cloud/ULTRA_TUNNEL_HANDOFF_2026_11_01.md).
**Node directo falló por DNS EAI_AGAIN en este entorno**; transporte Node
cubierto con mocks y replay real. VPS/Android físico pendientes, sin fusión
ni despliegue automático.
