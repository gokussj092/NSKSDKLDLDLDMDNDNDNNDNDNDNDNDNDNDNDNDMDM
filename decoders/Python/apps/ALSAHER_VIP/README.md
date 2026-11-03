# ALSAHER VIP 1.1 / build 2

Paquete `com.alsaher.vip`; proveedor Cloud fijo `alsaher-vip`.
Muestra aportada por el propietario mediante Archive.org. No se certifica que
sea la versión más reciente de una tienda ni se redistribuye su APK en Git.

## Resultado real

| Fuente | Versión | Servidores | HTTP | SSL | JSONsettings |
| --- | --- | ---: | ---: | ---: | ---: |
| Incluido `mtkConfig.zip/mtk.hs` |9.9.9|4|4|1|1|
| Actualizador remoto original |9.9.58|14|3|9|1|

La descarga real fue HTTP 200 con **80552 bytes** cifrados. El catálogo remoto,
sus 76 campos cifrados y el documento completo coinciden con la referencia
Java, CLI y worker aislado. El incluido también se comparó entero, por separado;
no sustituye al remoto. La referencia Java reutilizada tiene la misma receta
XXTEA (delta772515655), clave de formato y doble resta de unidades UTF16 que
`FileUtils`/`XxTea` de esta APK. Se reutiliza el motor ZiG existente sin cambiarlo.

Se preservan campos desconocidos, tipos, listas y JSONsettings. Los aliases
`cloud_get_api`/`cloud_post_api` se conservan vacíos en ambos documentos reales;
su tratamiento cifrado no vacío está cubierto por vectores sintéticos. No se
consultan esas APIs ni se registran nuevos formatos de archivo/exportación.

## Uso y backend

```bash
python decoders/Python/apps/ALSAHER_VIP/server_catalog_decoder.py
python decoders/Python/apps/ALSAHER_VIP/server_catalog_decoder.py /ruta/privada/catalog.enc
python decoders/Python/apps/ALSAHER_VIP/server_catalog_decoder.py --stdin < /ruta/privada/catalog.enc
```

GET fijo HTTPS con User-Agent original `okhttp/4.12.0`; sin Authorization,
cookies ni registro de dispositivo. **No requiere secretos nuevos ni cambios
Compose**. El worker solo descifra bytes; no recibe una URL ni hace red.
Cabeceras, URL del proveedor y perfiles permanecen fuera del catálogo público.

Solo Cloud: broker, worker, contrato, ficha/icono original y control individual.
Mínimo fuente64,60 fichas; versión efectiva superior y switches se conservan.
No se modificó Android ni se esperaron o lanzaron compilaciones Android.

[Expediente obligatorio](../../../../analysis/com.alsaher.vip/2/ANALYSIS.md)
y [pruebas](TESTING.md). Node directo devolvió REMOTE_NETWORK_DENIED en el
entorno de análisis; replay Node con bytes y resultado reales pasó con HTTP
simulado. Prueba Node real en VPS pendiente; sin despliegue ni fusión automática.
