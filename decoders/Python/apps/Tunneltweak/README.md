# Tunneltweak 6.2.1

Paquete `com.tunneltweak.loyalteams`, versión **6.2.1**, versionCode **51**.
Lectores extraídos del APK adjunto, sin depender de un método antiguo por su
nombre o extensión. Carpeta `decoders/Python/apps/Tunneltweak/`, rama
`feat/austroplus-vpn-13-0-1-decoders`, PR #96.

## Uso

Python 3.10+ y `pip install -r requirements.txt`. No requiere el APK.

```bash
python server_catalog_decoder.py > catalogo.json
python server_catalog_decoder.py copia_cifrada.json > catalogo.json
python server_catalog_decoder.py --stdin < copia_cifrada.json
python server_catalog_decoder.py --api-key-file mi_clave.txt > mi_catalogo.json
python file_decoder.py perfil.tut > perfil.json
python file_decoder.py perfil.tut --ask-password > perfil.json
python file_decoder.py perfil.tut --password-file clave.txt > perfil.json
python file_decoder.py < perfil.tut > perfil.json
python file_decoder.py --cloud-id 00000000-0000-4000-8000-000000000001 > perfil_cloud.json
```

El UUID del ejemplo es sintético: reemplazarlo por el UUID de una configuración
propia. `--cloud-id` solicita el recurso de la API original fija; no admite una
URL arbitraria ni enumera identificadores. El resultado conserva la respuesta
Cloud completa y sustituye su campo `config` por el JSON descifrado. Este camino
se verificó con respuestas simuladas; no se proporcionó un UUID real.

El lector de catálogo sin argumentos descarga y decodifica el catálogo real.
Archivo y stdin son siempre locales. `--api-key-file` es opcional para una clave
propia de suscripción: se envía como `x-api-key` exclusivamente al catálogo fijo
y se usa para su descifrado; si no se proporciona, no se envía esa cabecera.
No se incluyen claves de usuario. Los archivos de credenciales contienen una
línea UTF-8; se retira un único terminador CRLF/LF. Contraseñas no vacías de
hasta 4096 caracteres. Las contraseñas no se pasan como argumentos ni se imprimen.

## Archivos .tut

`ConfigManager` declara extensión `tut`, versión de configuración **6** y estas
rutas, comprobadas directamente en sus métodos:

| Variante | Operaciones |
|---|---|
| Exportación sin contraseña | Base64(IV16 + AES-128-CBC/PKCS5 ciphertext), clave UTF-8 `TunnelTweak2024!` |
| Exportación con contraseña | `TTPBE1:` + Base64(salt16 + nonce12 + ciphertext + tag16), PBKDF2-HMAC-SHA256/120000, clave de 256 bits, AES-GCM sin AAD |
| Lectura heredada del APK | Base64 → XOR byte a byte con `0x5A` → JSON |

Fuentes: `ConfigManager.encryptAES/decryptAES`,
`encryptWithPassphrase/decryptWithPassphrase`, `deriveKey`,
`decodeConfigLegacy`, `exportConfig` e `importConfig`; `MainActivity` conecta los
controles de importación/exportación y la petición de contraseña con esos métodos.
El lector devuelve el JSON antes de las transformaciones de importación de Android.
Mantiene `config_version`, mensaje, contraseña, campos multilínea, objetos
anidados, flags, caducidad, lista HWID y claves desconocidas con sus tipos.
La caducidad/HWID son metadatos del JSON, no claves criptográficas en estas rutas;
no se recalculan ni modifican. Solo se declara compatibilidad de archivo con
`config_version: 6`; no se certifica importación en otras versiones de la app.

`TTPBE1:` sin contraseña devuelve `PASSWORD_REQUIRED`; una contraseña incorrecta
o un tag alterado devuelve `AUTH_FAILED`. Un fallo GCM nunca invoca otro motor.
No se adjuntaron archivos exportados reales: la paridad se verificó con vectores
sintéticos producidos por los métodos criptográficos Java recuperados del APK.

## Catálogo y variantes de transporte

Endpoint original: `https://tunneltweak.com/api/servers`.
`ServerConfigManager.fetchFromUrl` envía User-Agent `TunnelTweak/1.0 (Android)`,
`ngrok-skip-browser-warning: true`, `x-app-version: 51` y `x-cfg-keyed: 1`.
El broker Cloud usa esas mismas constantes, sin aceptar URLs externas.

`SecureConfigEncryption` utiliza Base64(salt16 + nonce12 + ciphertext + tag16),
PBKDF2-HMAC-SHA256/**10000**, clave de 256 bits, AES-GCM sin AAD y constante
`TunnelTweak-Secure-v1`. Es una receta diferente de TTPBE1. La app prueba primero
la clave de suscripción, si existe, y después la constante pública; ambos caminos
requieren autenticación GCM. También se observaron JSON directo y Base64(JSON)
como formatos de catálogo heredados. No existe una segunda capa por campo en
los modelos `SSHServer` y `SSHServerConfig` de esta versión.

La respuesta real es `{ "data": "cifrado", "announcement": "..." }`. La salida
mantiene todo el sobre y convierte `data` en objeto:

```json
{
  "data": {"servers": [], "configs": {}},
  "announcement": "..."
}
```

La forma ilustra la estructura; no es una muestra real ni un catálogo válido
vacío. En la descarga verificada el 2026-10-20 (UTC), el catálogo público contiene
**1 servidor y 53 configuraciones**. No se descartan servidores invisibles,
niveles de acceso, IDs, `update_meta`, anuncio ni campos desconocidos. El número
corresponde a la respuesta pública disponible, no a un total inferido de otros
planes de suscripción. No se probó una suscripción real.

`ServerConfigManager` busca `assets/data_encoded.txt` como fallback, pero ese
archivo **no existe en el APK adjunto**. Por ello no se fabrica ni presenta un
catálogo local de ejemplo. Cachés privadas: `server_cache.enc` y
`bot_server_cache.enc`. El catálogo de bot depende de una URL guardada en las
preferencias de la instalación: no hay un segundo endpoint fijo recuperable
para añadir. Las copias autorizadas de esas respuestas se pueden leer offline.

## Cloud UUID y enlaces

`net/CloudConfigClient.DownloadTask` realiza GET a
`https://tunneltweak.com/api/cloudconfig/<UUID>` y toma `config`; lo importa con
`ConfigManager`. Se añadió ese mismo transporte al lector de archivos mediante
`--cloud-id`, con UUID de formato estricto y host fijo. No se implementa la carga
POST de configuraciones, que no es necesaria para leerlas.

El manifest admite `file`, `content`, HTTP(S) y FTP con nombres terminados en
`.tut`: son transportes del mismo archivo. La app también interpreta enlaces
VMess, VLESS e Hysteria2 estándar en texto; no se encontró otro cifrado propio
para justificar un tercer decodificador. El CLI no descarga URLs arbitrarias.

## Integración y distribución

- `file_decoder.py`: lector local y UUID; `server_catalog_decoder.py`: catálogo.
- `codec.py` y `network.py`: soporte autónomo incluido en el ZIP.
- `worker_bridge.py`: adaptador exclusivo del repositorio para credenciales en
  stdin y compatibilidad con el `.tut` genérico DES/GCM anterior. No se necesita
  para ejecutar los dos lectores autónomos del ZIP.
- Cloud acepta `credentials: {"password": "..."}` para `.tut` en el canal existente;
  no acepta HWID para este formato. Los errores de contraseña conservan los códigos
  públicos existentes. No se modifica Android ni sus diálogos.
- El inventario C0 de 240 no cambia; C8 sigue en 246. Solo se reemplaza la ruta
  efectiva `.tut`, conservando byte a byte el resultado de los motores anteriores.
- Proveedor fijo `tunneltweak`; versión mínima del catálogo público **11**.
  El worker recibe bytes y no realiza descargas. La ficha Cloud consulta el
  catálogo público, sin clave de suscripción; las claves propias solo se usan
  mediante el CLI autónomo.

Icono launcher original `base.apk:res/mipmap-xxxhdpi-v4/ic_launcher.png`, recurso
`0x7f0f0000`: **192×192**, **31632 bytes**, SHA-256
`e7eec681345d4fcbefd699857d2e456d42d7cd6568488d64d578b9d489263a72`.
Se conserva idéntico en esta carpeta y en
`cloud/web/public/server-vpn-icons/tunneltweak.png`.

Límites: archivos de 5 MiB, catálogo/salida de 8 MiB, profundidad 64, plazo de
red de 25 segundos, HTTP 200 y contenido sin compresión; sin redirecciones.
Se rechazan padding, tags, JSON ambiguo, Unicode inválido y entradas truncadas.
Ningún APK, catálogo real ni resultado privado forma parte del repositorio o ZIP.
El GET directo del broker Node no se pudo verificar en este entorno: su DNS
nativo falla también para GitHub; no se relajaron las restricciones. El CLI
real, el worker y las pruebas del broker con DNS controlado sí se verificaron.
Ver `TESTING.md` y `manifest.json` para la evidencia y límites de validación.
