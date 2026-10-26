# HA Tunnel Plus 1.7.1 (76)

Paquete `com.hatunnel.plus`. Rama independiente
`feat/ha-tunnel-plus-1-7-1-decoders`, creada desde `main` en
`27cc8894469a5742e73c3d2a0a83cdf836663878`.

**Archivos históricos `.hat`: lector completo verificado. Catálogo remoto de
1.7.1: pendiente de recuperar sus recursos y constantes DexProtector.** No
confundir ambos soportes. La ficha muestra el PNG original con `remote:null` y
`decodeEnabled:false`, incluso si se fuerza su disponibilidad. Catálogo mínimo
52, 48 fichas. No hay despliegue, fusión ni anuncio C11 en esta entrega.

## Archivos y Termux

`hat_decoder.py` es autónomo e importable. Conserva todo el JSON: configuración,
perfil, descripción, protecciones, campos desconocidos, listas, nulos y opciones
anidadas. Sustituye el recorte del antiguo script Python por JSON estructurado.
Admite Base64 con BOM o saltos de línea, valida el sobre y devuelve errores sin
incluir la entrada. Solo transforma los cuatro campos `profilev5` conocidos;
los opcionales ausentes/nulos/textos siguen disponibles.

```sh
pkg install python
python -m pip install pycryptodome
python hat_decoder.py configuracion.hat -o resultado.json
python hat_decoder.py configuracion.hat --raw-fields -o original.json
cat configuracion.hat | python hat_decoder.py -
```

El archivo de salida se crea con permisos 0600 y nunca sobrescribe otro archivo.
Sin `-o`, el contenido completo se imprime en terminal. `--raw-fields` conserva
los portadores originales: un texto que casualmente sea Base64 no puede
distinguirse inequívocamente del XOR sin metadatos del exportador.

Formato histórico verificado: Base64 → AES-128-ECB/PKCS7 → UTF-8 → JSON;
cuatro campos `profilev5` usan Base64/UTF-8/XOR por unidades UTF-16 Java.
ECB no autentica el documento. Validar padding y JSON no demuestra autoría.
La constante histórica no se presenta como recuperada de este APK protegido.

La API Cloud con `full_hat=True` usa este mismo script. C0 y stdout C2 legado
siguen con su ruta original. La detección previa de portadores Xhypher completos
renombrados a `.hat`/`.bdnet` sigue intacta. No se añade una extensión inventada
ni se registra `.json` como formato general de HA Tunnel.

## Catálogo e importaciones

La aplicación contiene `resources/servers.json`, `methods.json`, `customs.json`,
`allowed_apps.json` y `whatsnew.json`. Son recursos protegidos por DexProtector,
no JSON que pueda abrir el lector `.hat`. El actualizador `ResourceUpdater`
hace GET a una URL protegida; `MainActivity.processUpdate` trata `servers` y
`allowed_apps` como cadenas JSON y aplica `AESEncryption.decrypt` a `methods`
con otra constante protegida. La caché SQLite tiene su propia clave.

No se habilita broker ni selector administrativo de descarga sin conocer y
validar esa fuente fija y sus bytes completos. Tampoco se confirma un protocolo
independiente de texto/enlace/ID cloud: no se inventa uno por analogía con otras
aplicaciones. Los endpoints de facturación/intercambio de tokens no son el
catálogo y no se consultaron.

En `ExportActivity`, password, identificador del dispositivo y caducidad se
agregan a `protextras` antes del cifrado exterior. Password e identificador se
comparan mediante hashes después de abrir el documento; no son directamente la
clave AES del archivo. Las cadenas, digest y transformación actuales permanecen
protegidos. No se afirma compatibilidad 100 % de 1.7.1 sin la comparación real.

## Evidencia y continuación

[ANALYSIS.md](ANALYSIS.md) conserva hashes, consumidores y tokens concretos.
[TESTING.md](TESTING.md) distingue pruebas sintéticas, muestras históricas y
Android pendiente. `manifest.json` registra ese alcance para futuras sesiones.

`scripts/apk_analysis/ha_runtime_capture.py` permite leer constantes y recursos
incluidos desde el APK original en un dispositivo de pruebas autorizado. No
extrae perfiles del usuario ni inicia VPN, cambia verificaciones o utiliza
cuentas. Debe ejecutarse con el PID explícito de la aplicación ya abierta;
requiere el APK de SHA-256 exacto y Frida 17.24.3. Guarda todo fuera de Git en un
directorio privado nuevo y produce solo recuentos en stdout. Incluye un vector
sintético de las funciones originales para contrastar el cifrado y `hideParams`.
La herramienta tiene comprobada su sintaxis; la captura completa sigue pendiente.

```sh
python -m pip install frida==17.24.3 frida-tools==14.11.0
# Iniciar Frida server coincidente en el dispositivo de pruebas propio.
adb forward tcp:27042 tcp:27042
adb shell pidof com.hatunnel.plus
python scripts/apk_analysis/ha_runtime_capture.py \
  --apk /privado/ha-1.7.1.apk --pid PID --output /privado/ha-capture
```

Los siguientes pasos son recuperar esos recursos, reproducir el algoritmo con
una referencia original, validar la respuesta completa del GET fijo y solo
entonces habilitar proveedor/switch. No usar esta ficha como anuncio de soporte
remoto terminado. APK, SO, AVD, inventarios completos, capturas, configuraciones
y credenciales reales quedan fuera del repositorio.
