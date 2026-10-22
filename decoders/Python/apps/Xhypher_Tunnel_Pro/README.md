# Xhypher Tunnel Pro — 43 (43)

Paquete `pro.xhypher.tunnel`; proveedor fijo `xhypher-tunnel-pro`.
Integración del backend en el PR #96. Python >=3.10 y `pycryptodome==3.23.0`;
ningún APK, SO, Android, cuenta o credencial de servicio se necesita en runtime.
Se reutilizan las primitivas del lector histórico `decoders/Python/renz.py`.

## Métodos confirmados en este build

| Entrada | Método recuperado | Resultado |
| --- | --- | --- |
| Catálogo remoto e inicial | Base64 → AES-128-CBC con SHA-256(seed)[:16] e IV fijo → XXTEA de delta propio | JSON completo de Servers, Networks, credenciales globales y metadatos |
| Campos tipo 0 | Misma cadena Base64/AES-CBC/XXTEA | Nombres, puertos, banderas, DNS, certificados, UUID y campos de opciones |
| Campos tipo 1 | Base64 → Threefish-256, HKDF-SHA256 de 16/32 bytes, tweak `(índice, índice*192)` → AES-128-CBC | Hosts, SNI, paths, payloads y configuración V2Ray completa |
| Campos tipo 2 | U+200B/U+200C con relleno U+200D, intercambio de bits adyacentes y XOR 0x5A → XXTEA → AES-256-CBC con IV prefijado | Usuarios y contraseñas; PBKDF2-HMAC-SHA256, 100000 iteraciones |
| Archivos `.xhypher` existentes | Ruta RENZ canónica, con las dos extensiones puntuales anteriores | Compatibilidad histórica y campos actuales, sin cambiar inventario ni extensiones |

La ruta moderna sensible usa su IV prefijado real, sin descartar bytes de la
contraseña descifrada. Los campos tipo 1 conservan ceros del ciphertext hasta
el siguiente límite de bloque AES antes de validar PKCS#7: el recorte byte a
byte observado en el código nativo cortaría tres campos de la descarga real.
El resultado recuperado coincide con JDK independiente; los bloques Threefish
originales de esos tres casos también se ejecutaron y compararon íntegramente.

**Estos formatos CBC/XXTEA/Threefish no tienen autenticación criptográfica.**
Padding, longitud y estructura permiten validar el formato; no demuestran
integridad frente a modificaciones intencionales. El lector de catálogo rechaza
el documento completo si un campo cifrado conocido falla; no presenta éxito
con una fracción de los registros.

## Fuente y conservación del documento

Única fuente oficial confirmada en el updater de este APK:

`https://raw.githubusercontent.com/XyrussProject/infinite88/refs/heads/main/xhyphertunnelpro888.hs`

Descarga autorizada del 2026-10-22: **HTTP 200, 1386712 bytes, Version 2.665,
57 servidores y 1161 redes/payloads**. Se procesan 10055 campos conocidos,
7363 no vacíos. El JSON completo coincide con JDK, CLI HTTPS real, CLI stdin
fuera del repo y proceso Cloud aislado (`isPartial:false`). Estos recuentos
son observaciones, no límites ni cantidades fijas de servidores únicos.

El catálogo inicial real `res/aa/e.rj` también coincide completo: **Version
1.0.0, un servidor y una red**, 21 campos procesados / 15 no vacíos.
No se omiten datos por filtros de interfaz. Se conservan orden, duplicados,
valores vacíos/nulos, tipos, todas las listas, notas, opciones y claves
desconocidas; JSON internos de configuración permanecen como texto exacto.
No se elige un host aleatorio, reemplazan marcadores o inicia una sesión VPN.
Las credenciales globales ya forman parte del catálogo; no se inventa un feed
de usuarios separado.

## Uso

```bash
python server_catalog_decoder.py --download
python server_catalog_decoder.py copia-catalogo.txt
python server_catalog_decoder.py --stdin < copia-catalogo.txt
python file_decoder.py perfil.xhypher
```

Ambos lectores exponen `run(data: bytes) -> str`. El auxiliar de archivos usa
la ruta RENZ existente y conserva su envoltura JSON de compatibilidad. No se
aportó una exportación real independiente de build 43; el soporte específico
de perfil se comprueba con vectores sintéticos JDK, no con una certificación
de exportador o un roundtrip Android.

El APK distingue `xhyphertunnelpro://` de un mecanismo de enlaces cortos
`xhypher://` con consulta de repositorio. No se incorpora esa consulta, no se
usa ninguna credencial incrustada de servicios y no se fabrican respuestas.
Los aliases históricos del bot conservan su tratamiento de payloads completos.
El tipo nativo 3 abre un DEX de comprobación de APK, no un catálogo o perfil:
no se anuncia como método de descifrado de configuraciones.

## Integración Cloud

- Bridge privado e identificación fija en el worker aislado.
- Una URL HTTPS aprobada, DNS IPv4 público validado, TLS y cero redirecciones;
  el cliente no elige destinos. Control administrativo individual incluido.
- Contrato de salida: proveedor/kind correctos, Servers y Networks completos,
  texto y JSON estructurado iguales y ausencia de salida parcial.
- Icono raster original exacto: `res/i/c8.png`, **512×512, 102502 bytes**,
  sin redibujar, convertir o redimensionar.
- Catálogo mínimo **32**, **34 fichas**, respetando versión persistente y
  switches. La disponibilidad efectiva requiere actualizar la VPS con las
  funciones Cloud habilitadas; esta entrega no hace despliegues.

## Reproducción

`TESTING.md`, `manifest.json` y `tests/golden/xhypher_*` contienen alcance y
referencias. El oracle JDK no importa el lector Python; el oracle ARM64 verifica
el hash exacto del SO original y ejecuta solo primitivas offline con memoria
limitada, sin JNI ni red. JADX reportó cinco errores generales; no se afirma
una descompilación perfecta. Las rutas documentadas se inspeccionaron por separado.

Las herramientas LSParanoid existentes ahora aceptan nombres renombrados de
campo/método; resolvieron **1987 literales en 81 archivos, 2252 cadenas de
inventario**. Se conservan únicamente fuentes reutilizables y fixtures sintéticos:
APK/SO, inventarios de cadenas, catálogos reales y datos descifrados quedan fuera
de Git. No se fusiona, despliega, publica APK ni modifica novedades C11.
