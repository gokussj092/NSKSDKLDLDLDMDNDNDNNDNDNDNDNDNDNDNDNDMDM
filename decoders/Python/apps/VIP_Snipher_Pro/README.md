# VIP Snipher Pro 2.9 (29)

Paquete `dev.renz.soft.vipsnipherpro`. Lector completo **offline** de catálogo,
worker privado y ficha `vip-snipher-pro` con el PNG original. Catálogo mínimo
**59**, conservado por instrucción del propietario para el lote aún sin
desplegar; **53 fichas**. No modifica Android, el panel ni los switches.

**Descarga remota pendiente:** el GET fijo recuperado del actualizador devuelve
HTTP **404** en peticiones anónimas desde este entorno, confirmado de nuevo
el 2026-11-01:

`https://raw.githubusercontent.com/Civ3snipher/NEW-VIP-SNIPHER-PRO-3/refs/heads/main/update.json?ref=main`

La URL histórica sin `-3` también devuelve 404. No se reemplaza por una fuente
inventada ni por el asset antiguo. La ficha conserva `remote:null`, incluso
con el interruptor global activado, y no hay un broker público de descarga.
El worker puede procesar bytes autorizados offline. Para habilitar la descarga
es necesario obtener y contrastar un catálogo real de la fuente vigente.

**Versión y cabeceras revisadas:** el HTML vigente de Google Play sigue
anunciando **2.9**; el original analizado es **2.9 / build29**, también el más
reciente listado por APKPure. `VIPSNIPHERPROMain.s.getHeaders()` añade
`Accept: application/json`, `X-GitHub-Api-Version: 2022-11-28` y una
autorización propia del desarrollador. No añade un `User-Agent` personalizado.
La herramienta envía por defecto las dos cabeceras públicas; su
`VIP Snipher Pro/2.9` identifica a la herramienta, no al cliente Android.
No copia ni utiliza la autorización del APK. Tres peticiones sin ella
(agente por defecto, de herramienta y Dalvik) devolvieron 404. Esto no prueba
que falle una petición autenticada de la app ni que el servicio esté caído.

Para solicitar la **misma URL exacta del APK**, la herramienta permite que el
operador suministre una autorización válida mediante el secreto de entorno
`SPDECODE_VIP_SNIPHER_AUTHORIZATION` (valor completo `Bearer …` o `token …`).
Solo `--download` lee ese secreto; el lector offline y el worker no lo necesitan.
No se guarda en el código, en los resultados ni en argumentos de línea de
comandos. La descarga permanece limitada a esa fuente y no sigue redirecciones.
Este soporte no acredita acceso al repositorio del proveedor: no se dispone de
una credencial autorizada del operador y no se ha validado un catálogo remoto.

## Uso

```sh
python -m pip install -r requirements.txt
python server_catalog_decoder.py copia-catalogo.txt
python server_catalog_decoder.py --stdin < copia-catalogo.txt
# Reintento explícito de la única fuente del build; actualmente HTTP 404:
python server_catalog_decoder.py --download
```

`run(data: bytes) -> str` nunca accede a red. Descarga explícita limitada a
8 MiB / 25 segundos, sin redirecciones, HTML, URL del cliente o fallback.
Python >=3.10 y PyCryptodome 3.23.0. Para ejecutarlo fuera del checkout conservar
`../../renz.py`, `../HTTP_FenixVPN/codec.py` y `field_names.json`, además de las
dependencias declaradas. No necesita APK, SO, cuenta Android ni contraseña
personal durante el descifrado.

## Método y evidencia

| Selector original | Receta |
| --- | --- |
| 0, exterior y campos generales | Base64 → AES-128-CBC/PKCS7 → XXTEA con delta 2052510689 → restar 2 a cada byte |
| 1, hosts/payloads/configuración V2Ray | Base64 → Threefish-256, tweak **(0,0) para todos los bloques** → AES-128-CBC/PKCS7 |
| 2, usuarios/contraseñas | Base64 → XXTEA → AES-256-CBC/PKCS7 con IV prefijado de 16 bytes |

Las constantes del formato coinciden con el material histórico
`renz.RENZ_KEYS['vipsnipherpro']`. Se fijan en este lector para no cambiar los
otros formatos de RENZ. Clave del modo 0: SHA256(seed)[:16]; modo 1: HKDF-SHA256
con salt de 16 bytes para la clave AES y de 32 para Threefish, info vacía;
modo 2: PBKDF2-HMAC-SHA256, 100000 iteraciones, salt completo y salida32.
La clave XXTEA sigue el tratamiento C de sus primeros 16 bytes.

`libovpn3.so` ARM64, SHA256
`0e9f382d7d7249a55c9fcfcd21a1e02c01c98b506a7d95c518a1931e7c809a66`:
seed `0x27f688`, IV `0x27f6a8`, salt HKDF `0x27f668`; `FIXED_SALT` duplicado
en `0x27f6f4`, referenciado por GOT `0x86b188` para PBKDF2. Dispatch
`RenzUtils_decrypt` en `0x4949a8`, `decryptSpecial` en `0x494208`,
`decryptSensitive` en `0x49469c`. `aes256Decrypt` (`0x498c78`) usa el IV
prefijado y valida padding. No descartar caracteres de la contraseña.

Rutas DEX: `VIPSNIPHERPROMain.P()` fija la URL; `h91.b/c` llama a
`RenzUtils.decrypt` con los selectores; `c.x()` abre el catálogo incluido.
Los consumidores de `VIPSNIPHERPROMain` y sus métodos de presentación confirman
los mapas explícitos de campos. Se preservan los demás miembros, tipos,
flags, opciones, listas, duplicados y metadatos, sin elegir un host aleatorio.
El JSON V2Ray interno permanece texto exacto. Un campo conocido inválido
rechaza el documento completo.

El recorte nativo de ceros de Threefish corta bytes legítimos de **dos campos**
del asset. El lector conserva esos bytes hasta el siguiente límite AES y exige
padding/UTF-8 válidos; JCA y los bloques Threefish originales coinciden. No se
afirma ejecutar el JNI completo o imitar ese recorte defectuoso. Estos formatos
**no tienen MAC**: padding y estructura no autentican cambios intencionales.

## Resultado y alcance

Asset real `res/aa/d.js`: **Version 3.0.22, 14 servidores / 280 redes**,
**2441 campos conocidos / 1750 no vacíos**. Documento completo igual a Java
independiente, Python, CLI stdin y worker aislado; ocho casos de primitivas
ARM64 originales iguales. Gateway interno recibe toda la salida con transporte
simulado. Ninguna sesión VPN, emulador ni conexión Android se ha probado.

`.vipsnipherpro` y `vipsnipherpro://` ya existen en RENZ y se conservan. No se
aportó un perfil exportado de build29; no se anuncia una actualización o
certificación de ese exportador. La importación `.js/.rj` vista en el APK es
actualización de catálogo, no una justificación para capturar esos sufijos
globalmente. C0 **240**, C8 **254**, overrides **28**, intactos.

PNG original exacto `res/i/cb.png`: **512×512, 25374 bytes**, SHA256
`6a2ecaacc5fdf2a20f23cf31a58838854d7573dfb58c738274e150c31978e1e6`.
No redibujado, conversión ni redimensionado. Ver `TESTING.md`, `manifest.json`
y `docs/cloud/VIP_SNIPHER_90NET_HANDOFF_2026_10_31.md` para recuperación.
