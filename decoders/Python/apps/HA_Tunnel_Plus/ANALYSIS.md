# Evidencia de HA Tunnel Plus 1.7.1 — 2026-11-01

## Procedencia y límites

| Muestra | Bytes | SHA-256 |
| --- | ---: | --- |
| APK protegido anterior | 25014133 | `741e283ba3ee4b04b6988d5842d38491a51fa0bddfaf52d9c6bca9e6245ad051` |
| APK MOD aportado por el propietario | 28602472 | `49784eadfcfb5d0ec9cbb5e24b96a0f02d5ed53314b0b068ff261c8a0ad6c4e0` |

Ambos declaran `com.hatunnel.plus`, 1.7.1/code76. Certificado anterior:
`b3ad016bcd4f267eac311aa37738811b4c959b9360f4edaf79eeb467cded9132`.
Certificado MOD: `aba330e2fd110da02c277765be6241584213cb8e876d143aff9c889978696071`.
El MOD no se presenta como una descarga original de Play ni como prueba de
que todos sus métodos coincidan con el APK protegido. Launcher MOD:
`app.fast.ssh.MainActivity`; protegido: `com.hatunnel.plus.jlvfyyvkjayic`.

La investigación anterior quedó bloqueada en recursos DexProtector y ausencia
de `VpnProfile`; el emulador Android sufrió watchdog de `system_server` y la
captura Frida no terminó. No era evidencia de rechazo de Frida por la app.
La herramienta `ha_runtime_capture.py` permanece para esa muestra exacta;
no se ejecutó una nueva captura Android en esta entrega.

## Recuperación reproducible de la muestra MOD

Los cinco JSON de `assets/resources/` están claros: servers1764, methods956,
customs521, allowed_apps2711 y whatsnew448 bytes. Coinciden en tamaño con
las longitudes declaradas por las cabeceras protegidas anteriores; ahora se
comprobó el contenido. DEX6 contiene `app.fast.ssh.core.VpnProfile`.
JADX1.5.6 terminó con 68 errores; no se declara una descompilación completa.

Las cadenas relevantes se resuelven con `com.liapp.y.m766..m773(int)`.
`ha_mod_strings.py` reproduce el parser nativo SGB2 de
`libewutwwzwb.so`, sin ejecutar JNI_OnLoad, loader, comprobaciones del sistema
ni procesos Android. Solo emula memoria y las funciones puras 0x2e89c/0x2ecb4.
El bloque de `assets/.ewutwwzwb.dex` mide2746467 bytes,10005 grupos,58864 entradas,
1684567 bytes de payload. Se recuperaron **925 cadenas relevantes**, con
igualdad completa entre la herramienta repetible y el inventario inicial.
El APK queda fijado por hash: no aplicar offsets a otras compilaciones.

| Consumidor recuperado | Resultado |
| --- | --- |
| `ResourceUpdater` | Volley JsonObjectRequest GET fijo, sin body ni cabeceras propias |
| `MainActivity.processUpdate` | JSON de servers/allowed_apps y AES de methods |
| `AESEncryption` | SHA-1 UTF8 de frase, primeros16 bytes, AES/ECB/PKCS5Padding |
| `ExportActivity.getContent` | Perfil abierto o profilev5/protextras según seis checkboxes |
| `VpnProfile.hideParams` / `HideUtil` | Solo connection_mode, custom_payload, custom_sni, custom_host |

Frase pública de `.hat`: `8515D40BD04D8C97`; clave derivada Base64
`zbNkuNCGSLivpEuep3BcNA==`, idéntica al lector histórico.
Frase pública de métodos: `3A0183FADC903782`; clave derivada hex
`caf88ec7d2df3146e082dbfc89ff1430`.
Clave XOR (18 unidades UTF16 Java): `` **rVg7EkL~c2`D[aNn ``.
Se aplica XOR por char Java → UTF8 → Base64; la inversión conserva emoji.
Son constantes del formato, no secretos de cuentas. La caché SQLite y las
rutas de facturación no intervienen en este GET y no se consultaron.

## Descarga real y documento completo

Origen fijo: `https://www.hatunnel.me/resources/main.txt`, HTTP200,
text/plain,296647 bytes. SHA-256 del cuerpo original:
`dae31d366acf3f8abc5f58cb306a391af2eb70dec52a3104b30dda2551bd44fa`.
La CLI repitió una descarga real y obtuvo el mismo documento completo.
El GET inicial empleó `Dalvik/2.1.0 (Linux; U; Android 11)`; CLI/broker emplean
el prefijo `Dalvik/2.1.0`. No se atribuye esa cadena completa a un dispositivo
instrumentado. No se necesitó sesión, token ni renovación adicional.

| Sección | Versión | Registros |
| --- | --- | ---: |
| servers | 2022.01.08.02 | 13 |
| methods | 2026.06.27 | 644 |
| allowed_apps | 2021.02.04.00 | 4 grupos |

Se contrastó el JSON entero, recursivamente y con tipos, entre JCA/Gson,
Python, CLI con GET real y worker aislado: todos los `conf`, las secciones y
`message` conservados. El LF literal dentro de methods se acepta como Android;
no se abrevia ni se repara mediante reemplazo de caracteres. El incluido
contiene13 servidores y4 métodos: se registra aparte y no sustenta el éxito
remoto. Cuerpos, inventarios y documentos completos se guardan privadamente.

## Exportación abierta y evidencias reales

La rama sin protecciones de `ExportActivity.getContent` guarda `profile` y
`description`. La rama protegida deja profile vacío, usa profilev5 con cuatro
campos ocultos, descriptionv5 y protextras. Contraseña e ID usan MD5 posterior
al descifrado; no son claves del sobre. Protecciones conocidas: anti_sniff,
mobile_data, block_root, password/password_value, id_lock/id_lock_value,
expiry/expiry_value.

El MOD además modifica `HomeFragment.finishImport` para retirar protecciones
y su `getProtextras` devuelve null; esas modificaciones no se atribuyen al
original protegido. El escritor reproduce la rama de exportación abierta y
la primitiva recuperada, preservando el perfil completo y la nota original.

| Archivo real histórico | SHA-256 entrada | Bytes entrada → salida |
| --- | --- | ---: |
| hat/test.hat | `1f58f2ca5cc35826cdd0d4b2de920227d9f54de3182d3269c24a0f95c117ee41` | 2136 →1240 |
| hat/test1.hat | `477292c15dff2103f49421b83d4d3aafbac67aac662610492b6bb904b7d6de34` | 2924 →1984 |

Ambos abrieron, exportaron y reabrieron con igualdad completa de perfil,
nota y metadatos con referencia Java independiente y worker. Cada perfil
contiene16 campos. Se retiraron los contenedores conocidos de protección;
no se agregaron credenciales o valores inventados. Los originales históricos
ya estaban en el repositorio: no se añaden copias ni nuevos datos reales.
No hay archivo exportado mediante ejecución actual del MOD, prueba de
importación física, conexión VPN, compilación Android ni despliegue.
