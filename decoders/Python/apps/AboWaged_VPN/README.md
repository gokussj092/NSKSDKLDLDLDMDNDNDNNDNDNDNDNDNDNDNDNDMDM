# AboWaged VPN 1.0

Paquete `com.modev.vpn`, versionCode **1**. Integración del backend en PR #96.
Python 3.10+ y PyCryptodome; no requiere APK, biblioteca nativa ni Android en
runtime. Instalar `requirements.txt` en un entorno virtual.

- `file_decoder.py`: archivos **`.awg`**, `run(data: bytes) -> str`.
- `server_catalog_decoder.py`: catálogo principal y selector UDP independiente;
  mismo contrato offline, CLI con descarga de dos fuentes HTTPS fijas.
- `codec.py`: formatos y validación estricta, sin red ni credenciales de usuario.

```bash
python -m pip install -r decoders/Python/apps/AboWaged_VPN/requirements.txt
python decoders/Python/apps/AboWaged_VPN/file_decoder.py perfil.awg
python decoders/Python/apps/AboWaged_VPN/file_decoder.py - < perfil.awg
python decoders/Python/apps/AboWaged_VPN/server_catalog_decoder.py
python decoders/Python/apps/AboWaged_VPN/server_catalog_decoder.py --source servers
python decoders/Python/apps/AboWaged_VPN/server_catalog_decoder.py --source udp
python decoders/Python/apps/AboWaged_VPN/server_catalog_decoder.py copia-catalogo.txt
python decoders/Python/apps/AboWaged_VPN/server_catalog_decoder.py --stdin < copia-catalogo.txt
```

El CLI sin argumentos descarga ambas fuentes; `run()` nunca descarga. El
bundle completo contiene `provider`, `complete:true` y `catalogs.servers` /
`catalogs.udp`. Una copia individual devuelve íntegro su documento original.
Si falta o falla una fuente del bundle se devuelve un error, sin truncamiento
ni informe de éxito parcial. No se permite elegir URLs arbitrarias.

## Contraseña personalizada

**No hace falta pedir una contraseña para descifrar `.awg` de esta versión.**
`ExportActivity.t()` escribe `isPassON` y `MyPass` dentro del JSON y cifra con
una clave fija de formato. `AboWagedMain.R()` abre el JSON antes de mostrar el
diálogo; `ViewOnClickListenerC3154l0.onClick()` compara el texto con `MyPass`.
Es una validación de importación de la app, no una KDF ni una clave del cifrado.
El lector conserva ambos campos, además de las restricciones de dispositivo,
caducidad y root; no necesita valores externos para abrirlos.

Esto se comprobó en **1.0 (1)**; no se generaliza a futuras versiones ni a otras
aplicaciones con cifrado derivado de una contraseña. No se añade una petición
de contraseña ni un parámetro `password` a este motor.

## Compatibilidad comprobada

El catálogo del APK contiene **1 servidor / 1 ajuste**, versión **1.0**.
La fuente remota consultada el **2026-10-23** contiene **12 servidores / 257
ajustes**, versión **4.6.3**; el selector adicional contiene **2 servidores UDP**.
Los tres documentos completos coinciden con JDK independiente, incluidos
campos vacíos, tipos y estructuras anidadas. El CLI HTTPS y worker entregan el
bundle completo, **102521 bytes** en la muestra observada.

`.awg` se valida con dos exportaciones sintéticas independientes, con y sin
bloqueo personalizado. **Pendiente una exportación real del usuario**; no se
presenta esa prueba sintética como una importación real en el teléfono.

Se descifran únicamente los campos y ubicaciones confirmados en el APK. Los
desconocidos permanecen intactos. `Server` en el perfil sigue siendo una cadena
JSON, con sus campos internos abiertos; no se cambia a un objeto. No se
modifican nombres, placeholders ni credenciales de conexión según `NoobLevel`;
se entrega el catálogo almacenado descifrado. Los servidores observados usan
`NoobLevel:0`. Los protocolos de conexión y la lógica `sLevelOne/Two` no forman
parte del cifrado del contenedor.

El icono es el PNG original **648×648 / 456508 bytes**, preservado por encima de
256 KiB, con copia idéntica en la ficha Server VPN. Proveedor fijo
`abowaged-vpn`, mínimo de catálogo **35 / 37 fichas**; mantiene controles y
versión persistente. `.awg` está en C8 y el bot; C0 permanece en **240** y C8
efectivo pasa a **249**. Sin cambios de diseño Android/web, despliegue, APK,
fusión ni novedades C11. Detección en clientes antiguos pendiente de una futura
actualización del cliente, separada del backend.

Ver [ANALYSIS.md](ANALYSIS.md), [TESTING.md](TESTING.md) y
[RESTORE.md](../../../../scripts/apk_analysis/RESTORE.md).
