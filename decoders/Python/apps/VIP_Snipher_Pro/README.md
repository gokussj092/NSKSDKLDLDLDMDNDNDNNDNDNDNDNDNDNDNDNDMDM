# VIP Snipher Pro 2.9 (29)

Paquete `dev.renz.soft.vipsnipherpro`. Descarga autenticada de la fuente exacta
del APK, lector completo de catálogo, worker privado y ficha `vip-snipher-pro`
con el PNG original. Catálogo fuente **59**, conservado por instrucción del
propietario para el lote aún sin desplegar; **53 fichas**. Android sin cambios.

**Descarga real validada el 2026-11-01:** GET autenticado **HTTP200**, **323244
bytes**, catálogo **8.0.61 /47 servidores /273 redes**:

`https://raw.githubusercontent.com/Civ3snipher/NEW-VIP-SNIPHER-PRO-3/refs/heads/main/update.json?ref=main`

La URL coincide literalmente con `VIPSNIPHERPROMain.P()`. Su
`s.getHeaders()` añade `Accept: application/json`,
`X-GitHub-Api-Version: 2022-11-28` y `Authorization`. La comprobación utilizó
la misma credencial incluida en el APK, únicamente en memoria y contra esa
fuente fija. No se guardó su valor en Git ni se accedió a otros endpoints.
Las respuestas 404 previas correspondían a peticiones sin autorización.

El HTML vigente de Google Play sigue anunciando **2.9**; el original analizado
es **2.9 /build29**, también el último listado por APKPure. El actualizador
no declara User-Agent propio. `VIP Snipher Pro/2.9` identifica a esta herramienta.

## Configuración del servidor

El backend lee la cabecera completa de `SPDECODE_VIP_SNIPHER_AUTHORIZATION`
como secreto de entorno; Compose la transmite solo a `web`. Su valor no forma
parte del código, catálogo público, estado de switches, errores ni petición
interna al worker. Para el despliegue del lote 59 debe provisionarse en
`/etc/spdecode/cloud.env` desde la cabecera del mismo original guardado.
El valor se mantiene fuera del repositorio y de argumentos de comandos.

La ficha ya tiene broker remoto. Requiere la autorización configurada, el
interruptor global y la disponibilidad individual; sin el secreto no ofrece
descarga. El panel puede desactivarla conservando el estado de los demás
proveedores. Solo se acepta el GET de la URL fija, DNS público y TLS verificado;
se rechazan todas las redirecciones, incluidas las del mismo host. No hay
fallback al asset antiguo ni URL/credencial suministrada por el cliente.

## Uso

```sh
python -m pip install -r requirements.txt
python server_catalog_decoder.py copia-catalogo.txt
python server_catalog_decoder.py --stdin < copia-catalogo.txt
# Descarga de la misma fuente; configurar antes el secreto de autorización:
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

Catálogo remoto real **8.0.61: 47 servidores /273 redes**, 2829 campos
conocidos/1974 no vacíos; igualdad completa Java/Python/CLI/worker. Seis casos
de primitivas ARM64 remotos iguales. El gateway valida también la respuesta
real completa del worker con transporte interno simulado; no se afirma
transporte Node real al proveedor. Ver TESTING.md para todas las métricas.

PNG original exacto `res/i/cb.png`: **512×512, 25374 bytes**, SHA256
`6a2ecaacc5fdf2a20f23cf31a58838854d7573dfb58c738274e150c31978e1e6`.
No redibujado, conversión ni redimensionado. Ver `TESTING.md`, `manifest.json`
y `docs/cloud/VIP_SNIPHER_90NET_HANDOFF_2026_10_31.md` para recuperación.
