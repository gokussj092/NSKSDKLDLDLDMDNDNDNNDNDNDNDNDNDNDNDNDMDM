# Wolf Custom VPN — build 16 / v1.11.06.1

Se adquirió la distribución pública del paquete core.vpn3jx.xtreme y se leyó el
manifiesto binario: build 16. El certificado extraído conserva SHA-256
bd6515d3f58f73aa59ae99ae1d2aff74c4e2665c3bd677fbefea77222e88fc6b.
Esto comprueba continuidad del certificado observado, no la firma criptográfica
completa del APK. Los hashes de APK/XAPK están en generated/identity.json.

## Cambio observado

La ruta de build13 /api/wolfcustom/newv1.txt devuelve HTTP 404. El nuevo DEX
llama a Libv2ray.cu, getVerNotes y gfc desde ConfigUpdate$configUpdate$1.
La descarga pasó a la función Go github.com/2dust/AndroidLibXrayLite.CU,
en libgojni.so ARM32, SHA-256
4df067b7c0c6d38730476ff94a950424c561be05cd4d31abf64b6f6a7f73425a.

La función CU en 0xfd7154 construye un POST al destino fijo
https://strongteam.co/api/wolfcustomv2/, con formulario hash=xsandokUpdatex y
Content-Type application/x-www-form-urlencoded. No configura un User-Agent
propio; el perfil de transporte utilizado es Go-http-client/1.1.
Este valor de formulario es metadato del cliente público, no una credencial
de cuenta o suscripción.

## Formato nativo nuevo

- Encrypt: 0xfd2878; decrypt: 0xfd2e0c; DO: 0xfd3b58.
- Argon2id v19: tiempo 3, memoria 8192 KiB, paralelismo 1, salida 32 bytes.
- Base64 de salt16 || nonce12 || ciphertext || tag16, AES-256-GCM, salt como AAD.
- El transporte de CU/Encrypt introduce una letra en el índice 3 del Base64;
  decrypt la elimina antes de autenticar. DO abre los campos y el catálogo
  incluido sin esa letra.
- Las dos entradas fijas del KDF son distintas. Se verifican sus hashes y sus
  referencias PC-relative en native_recipe.py y verify.py. Son constantes del
  cliente público distribuido; no se usan contraseñas personales ni API keys.
  Las evidencias no publican sus valores; el codec contiene lo necesario para
  implementar el protocolo del cliente.
- No hay aceptación de texto descifrado si falla la autenticación GCM.

El lector conserva builds13 y perfiles históricos. El módulo compartido ultra.py
no se modificó. No se cambian etiquetas, claves desconocidas, tipos ni listas.

## Herramientas y reutilización

acquire.py reutiliza sin cambios el descargador validado de
analysis/com.tunneldoom.http/432/tools/acquire.py, con URL fija por aplicación,
y añade identidad APK/certificado mediante Androguard.

Se reutilizan el instalador verificado scripts/apk_analysis/decompile.py y el
JAR completo JADX 1.5.6. La CLI se invoca en modo auto; el comando principal
antiguo del helper utiliza simple y no fue modificado. JADX terminó con errores
en métodos ajenos al camino revisado; no se afirma descompilación global completa.

Se reutiliza paranoid_strings.py sin cambios para LSParanoid: 7866 IDs y 498
fuentes; inventario de 9790 cadenas. Se normaliza únicamente la declaración de
array de la salida privada de JADX para la gramática del helper. Se ejecuta el
algoritmo propio de resolución, nunca la clase del APK.

go_inspect.py y elf_inspect.py existentes admiten ARM64. Se consultaron como
referencia y permanecen intactos. El nuevo native_inspect.py adapta la lectura
del pclntab a ARM32. wolf_native_constants.py y wolf_verify.py anteriores
siguen documentando build13; no se presentan como validadores de build16.

El oráculo nuevo tools/oracle usa la implementación independiente Go/x-crypto
de Argon2id y AES-GCM estándar. Python usa argon2-cffi y PyCryptodome. Se comparó
el JSON completo, incluidos todos los campos que el oráculo pudo autenticar,
no una muestra ni solo el recuento de servidores.

## Intentos y límites conservados

- Una primera adquisición falló por usar un nombre de API v1 inexistente en
  Androguard 4.1.3. Se corrigió a get_certificates() y se conservan los bytes
  privados para reintentos sin descargas repetidas.
- La primera descarga del JADX fijado recibió HTTP 504; el reintento validó los
  hashes del ZIP y del JAR.
- El lector anterior y las dos entradas nativas se contrastaron: solo DO,
  Argon2id con salt como AAD y sin eliminar letra abre el asset; solo la entrada
  de decrypt con eliminación en índice3 abre el remoto. inspect_carrier.py
  conserva este diagnóstico local, limitado a los candidatos extraídos.
- El ejecutable /usr/bin/go del entorno no era el compilador Go. Se instaló Go
  1.27.3 oficial con SHA-256 verificado en carpeta privada. El build del oráculo
  utiliza -buildvcs=false porque el checkout de investigación es una instantánea.
- No se ejecutó el APK, ninguna .so de la app, una sesión Android ni una conexión VPN.

