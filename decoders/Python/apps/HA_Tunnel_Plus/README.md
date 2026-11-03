# HA Tunnel Plus 1.7.1 (76)

Paquete `com.hatunnel.plus`. Catálogo remoto integrado en código y descarga
real completa verificada el 2026-11-01: **13 servidores / 644 métodos / 4 grupos
de aplicaciones**. Nuevo exportador `.hat` abierto conectado a Unlocked,
contrastado con dos archivos reales históricos y una referencia Java
independiente. **Importación física en Android y despliegue pendientes.**
No se certifica una exportación nueva creada ejecutando el APK.

La muestra MOD aportada permite recuperar recursos y constantes; tiene una
firma diferente del APK protegido anterior. [ANALYSIS.md](ANALYSIS.md) distingue
su procedencia y el alcance comprobado, sin afirmar equivalencia binaria.

## Descargar el catálogo completo

Solo Python y PyCryptodome; también puede ejecutarse en Termux:

```sh
python -m pip install pycryptodome
python server_catalog_decoder.py -o /privado/catalogo.json
python server_catalog_decoder.py /privado/respuesta-original.txt -o /privado/catalogo.json
cat /privado/respuesta-original.txt | python server_catalog_decoder.py -
python server_catalog_decoder.py --apk /privado/ha-171-mod.apk -o /privado/incluido.json
```

Sin entrada ejecuta el GET fijo `https://www.hatunnel.me/resources/main.txt`,
User-Agent `Dalvik/2.1.0`, sin body, autenticación ni renovación de sesión.
Volley no define cabeceras adicionales; Android añade su UA por defecto.
La cadena completa de UA depende del dispositivo y no fue capturada aquí.
`Accept-Encoding: identity` es una medida del transporte del script/broker,
no una cabecera personalizada recuperada de la aplicación.

`methods` es Base64 → AES-128-ECB/PKCS7 → JSON; la clave es los primeros
16 bytes de SHA-1 de la frase estática del actualizador. Las otras dos secciones
son objetos JSON (también se admite su representación como cadena, conforme
al consumidor Android). Se conservan todas las secciones, registros y campos
desconocidos, sin recorte de `conf`, flags o notas. El JSON exterior real
contiene un LF literal en el Base64: se admite como Android JSONTokener sin
reemplazar contenido mediante regex. El JSON interior sigue siendo estricto;
duplicados, esquemas incompletos y respuestas HTML se rechazan.

La salida `-o` se crea 0600, sin sobrescritura. Sin `-o` imprime el documento
completo: úsese una terminal privada. Límite 8 MiB, timeout 25 s, TLS normal,
sin redirecciones ni URLs elegidas por el llamante. `--apk` es una operación
separada sobre los cinco recursos incluidos; no sustituye la descarga real.

## Leer y exportar archivos

```sh
python hat_decoder.py configuracion.hat -o /privado/resultado.json
python hat_decoder.py configuracion.hat --raw-fields -o /privado/original.json
```

`hat_decoder.py` conserva el documento entero y la ruta histórica. La constante
AES histórica coincide con la recuperada de esta muestra 1.7.1. El lector
completo se usa con `full_hat=True` o al solicitar exportación compatible;
C0/C2 y la detección por contenido de Xhypher renombrado se conservan.

Unlocked usa `cloud/workers/python/exports/hat.py`: escribe el esquema abierto
de `ExportActivity.getContent`, `{profile: perfil completo, description: nota}`,
y lo vuelve a cifrar como `.hat`. Recupera los cuatro campos de `profilev5`,
retira sus contenedores de protección conocidos y conserva campos de conexión,
notas, metadatos desconocidos y tokens numéricos originales. No añade banner.
Variantes ambiguas, `profilev4` no vacío o protecciones desconocidas producen
`EXPORT_VARIANT_UNSUPPORTED`; el descifrado exitoso sigue disponible.

HA es el quinto formato negociado de Unlocked. El cliente Android actualizado
anuncia la capacidad adicional y acepta su artefacto; los clientes anteriores
siguen recibiendo exactamente los cuatro formatos previos. Se conserva el
switch administrativo existente y el estado desactivado por defecto, sin
activar producción automáticamente. No se introduce un protocolo cloud por ID.

## Estado del repositorio

Ficha e icono original, broker con DNS/TLS fijo, worker, validación del gateway
y control C12 conectados. Fuente Server VPN **59 / 58 fichas**, ocho `remote:null`;
C0 **240**, C8 **255** intactos. El despliegue deberá seguir el runbook de
versiones/cachés. [TESTING.md](TESTING.md) contiene comandos reproducibles,
evidencia real y límites. APK, inventarios de cadenas, respuestas y archivos
reales permanecen fuera de Git; las constantes públicas del formato no son
credenciales privadas de una sesión.
