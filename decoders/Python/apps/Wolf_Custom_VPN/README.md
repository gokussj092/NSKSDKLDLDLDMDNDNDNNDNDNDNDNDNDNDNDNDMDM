# Wolf Custom VPN — builds 16 y 13

Actualizado a core.vpn3jx.xtreme v1.11.06.1 / build16. Expediente completo,
herramientas y dependencias: [analysis/core.vpn3jx.xtreme/16](../../../../analysis/core.vpn3jx.xtreme/16/ANALYSIS.md).

El nuevo catálogo usa POST a la fuente fija recuperada de la biblioteca nativa.
El lector implementa Argon2id/AES-GCM con salt autenticado y el carácter añadido
al Base64 del transporte. Conserva los documentos de clave fija de build13 y
los archivos históricos; no se modificó ultra.py ni la ruta .wolftunnel.

El catálogo remoto completo observado contiene 41 servidores y 1851 redes.
Coincide íntegramente entre el oráculo Go independiente, Python y el worker.
No se entrega salida parcial ni se ejecuta el APK. Los recuentos pueden cambiar.

Uso desde esta carpeta:

~~~bash
pip install -r requirements.txt
python server_catalog_decoder.py > catalogo_privado.json
python server_catalog_decoder.py copia_cifrada.txt > catalogo_privado.json
python file_decoder.py perfil.wolf > perfil_privado.json
~~~

El proceso de descifrado del worker sigue sin red. Todas las rutas autentican;
un JSON o campo malformado después de autenticar no activa otro lector.

Se conservan la compatibilidad y los vectores de build13; su investigación está
en docs/cloud/WOLF_CUSTOM_VPN_HANDOFF_2026_10_31.md y scripts/apk_analysis/wolf_*.
El icono original anterior se mantiene. Los archivos de teléfono nuevos tienen
validación sintética y del contrato observado, sin certificación de exportador,
conexión VPN o despliegue VPS.
