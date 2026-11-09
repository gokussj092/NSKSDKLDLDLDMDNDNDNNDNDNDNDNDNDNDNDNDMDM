# SpeiGo VPN 1.3.48/build159

Dos catálogos separados: speigo-vpn-configs (configuraciones/Servers) y speigo-vpn-ssh (usuarios SSH/Usuarios). Cada entrada descarga y abre solo su propia fuente; no se fusionan documentos ni versiones. [Método, pruebas, herramientas y límites](../../../../analysis/netfree.mx.speigovpn/159/ANALYSIS.md).

Remotos reales:266 configuraciones, versión29, y1 entrada de usuarios, versión3. Se comprueba firma Ed25519, cada registro XChaCha20-Poly1305 y todos los campos internos. JSON entero verificado contra JCA/libsodium independiente y worker real; sin resultados parciales. Conserva campos desconocidos y todos los datos de cada documento.

server_catalog_decoder.py y ssh_catalog_decoder.py aceptan archivo o --stdin para lectura sin red. Sin argumentos descargan su fuente fija. run(bytes) es offline. TLS, origen fijo, controles del operador y mantenimiento independientes se mantienen. Icono PNG192x192 original. No se certifica formato de archivo exportado de teléfono.
