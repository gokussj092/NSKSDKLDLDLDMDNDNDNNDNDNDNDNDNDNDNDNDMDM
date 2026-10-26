# NPV 124.0.37: utilidad para Termux

El ZIP contiene `npv_termux.py`, el lector canónico `npvs.py`,
`npvs_identity.py` y `npv_recipient_capture.js`. Extraer juntos; no basta con
copiar solo el lanzador. Python 3.10+ y PyCryptodome 3.23.0.

```sh
pkg install python unzip
python -m pip install pycryptodome==3.23.0
unzip npv_termux_bundle.zip -d npv-tools
cd npv-tools
python npv_termux.py --help
```

Para abrir app-key v5 no se requiere root ni una identidad:

```sh
python npv_termux.py decode /ruta/perfil.npvs -o resultado.json
```

Una identidad propia compatible P-256 también se puede generar localmente para
pruebas. En Android, el botón de Ajustes utiliza la API, como se solicitó.

```sh
python npv_termux.py generate -o mi-identidad.json
python npv_termux.py decode /ruta/para-mi.npvs --identity mi-identidad.json -o resultado.json
```

Compartir con el creador del archivo únicamente `publicKey` (SEC1 comprimido
33 bytes, Base64URL sin padding). `privateKey` es PKCS#8 DER en Base64URL.
Generar una identidad nueva no abre archivos dirigidos a la identidad anterior.

## Capturar una importación en la aplicación oficial

Requiere NPV `com.napsternetlabs.napsternetv` **124.0.37 (577)** instalado en el
teléfono del propietario, root, Frida CLI funcional y un `frida-server` de la
misma versión/arquitectura iniciado como root y limitado a **127.0.0.1:27042**.
Instalar los binarios desde los [releases oficiales](https://github.com/frida/frida/releases)
siguiendo la [documentación Android](https://frida.re/docs/android/).
El script no descarga ni instala un servidor. La disponibilidad de los paquetes
de Frida en Termux depende de la arquitectura y distribución; `pip install
frida-tools` no garantiza que existan bindings Android compatibles. Comprobar
`frida --version` y `frida-ps -H 127.0.0.1:27042` antes de continuar. Si el cliente
no funciona en Termux, la misma utilidad se puede ejecutar desde un equipo con
el reenvío USB de Frida configurado hacia loopback.

Abrir NPV primero. Obtener el PID de ese proceso y ejecutar:

```sh
su -c 'pidof com.napsternetlabs.napsternetv'
python npv_termux.py capture /ruta/para-mi.npvs --pid 12345 -o npv-capturada.json
```

Sustituir `12345` por el PID obtenido. Durante los siguientes 120 segundos,
importar **ese mismo archivo** en NPV. Debe abrirse correctamente en la app
oficial. La utilidad conserva sus argumentos, resultado y excepciones; no
modifica identidades ni evita verificaciones. El observador se descarga al
terminar; no queda residente. El colector no guarda el log de Frida ni muestra
material secreto en terminal. Solo guarda JSON después de autenticar y
descifrar todo el archivo con el lector independiente. No sobrescribe archivos;
las salidas nuevas usan permisos 0600.

Si NPV usa la alternativa software, se captura el PKCS#8 cuando la app lo abre
y se deriva/comprueba su pública. Si usa una privada no exportable del Keystore,
el JSON contiene **un acuerdo ECDH limitado al SHA-256 y punto efímero de ese
archivo**, no una falsa clave privada exportada. Para otro archivo hay que
capturar otra importación. Root no garantiza exportar la privada de hardware.

En SP-DECODE Cloud: **Ajustes → Claves de destinatario NPV → Importar JSON
capturado**, activar **Usar mis identidades NPV** e importar el `.npvs`.
Si hay varias identidades que coinciden, elegir la generada o capturada. La
pantalla confirma que se enviará el material elegido al servidor para abrir el
archivo; desactivar la función impide adjuntarlo. El servidor no lo conserva.
La copia de la privada al portapapeles se solicita expresamente y se marca
como sensible; proteger ese JSON y el portapapeles.

**Validación:** pruebas sintéticas v5/v6 completas con JCA y worker, controles
del observador con mocks y colector con material sintético. La captura física
Android/root/Frida y el intercambio con un exportador oficial siguen pendientes
de una prueba en dispositivo. No se promete reproducir un Keystore de hardware
en Python ni compatibilidad universal del 100 % sin esa prueba.
