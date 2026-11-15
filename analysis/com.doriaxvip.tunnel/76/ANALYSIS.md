# Genis VPN 2.2.6 / build 76 — investigación y catálogo Cloud

2026-11-04. Investigación manual e implementación solicitadas por el propietario de SP-DECODE a partir de `https://play.google.com/store/apps/details?id=com.doriaxvip.tunnel`. Sin ejecutar la APK, iniciar túneles ni modificar Android.

## Identidad e insumos

Descarga real de APKPure con curl: HTTP 200, application/xapk-package-archive, 43.416.878 bytes. SHA256 XAPK `a19dcdb4cd1c1af697e7f2b7dd76af19f5e018313e2ae9a94ca752cb4a372831`. Base APK: `172da6fc4405d1cc4b70f69ce48b0f17f1b867c89a01017c991234f58ade229d`. Manifest verificado con Androguard: Genis VPN, `com.doriaxvip.tunnel`, versión 2.2.6, code 76; no se infiere la versión por una página de búsqueda ni se certifica como último Play.

Certificado extraído: SHA1 `327f73ad5bf2f808fccc4709c79c47f45bd61b32`. Presencia de esquemas v2/v3 y fingerprints, sin ejecutar apksigner ni afirmar verificación criptográfica completa de las firmas. Bibliotecas ARM64 inventariadas, sin ejecutarlas ni usarlas para el cifrado del catálogo.

## Método observado y comprobado

JADX 1.5.6 sobre `classes.dex`: exit 3 con 14 errores generales. Se conservaron las limitaciones; los métodos relevantes produjeron una receta que descifra documentos enteros reales y coincide con Java/JCA independiente.

1. `C0909b6` construye nombres mediante casts de enteros a bytes: `LICENSE`, `NIGHT_MODE`, `SSH_UDP`, `INPUT`. Carga los valores con Java Properties. Son constantes del formato, conservadas inline en el backend por indicación del propietario, sin requerir archivos de claves externos ni autenticación HTTP.
2. `AbstractC2568tf.m8169`: Base64 estándar, cabecera ASCII `WakkoDev`, salt de 8 bytes, encadenamiento MD5 de digest previo + contraseña UTF-8 + salt hasta obtener 48 bytes. AES-256-CBC/PKCS5Padding: primeros 32 bytes como key, siguientes 16 como IV. No es `Salted__`, GCM ni un esquema autenticado.
3. `AbstractC0684Vi.m4120` abre cada campo: Base64 URL, primeros 16 bytes IV, clave UTF-8 truncada/rellenada con ceros a 32 bytes, AES-CBC/PKCS5Padding. `C0909b6.m5349` aplica ROT de 26 − INPUT = 22 usando predicados Java Character sobre unidades UTF-16. Se preservan las claves JSON opacas; no se renombran.
4. Censo previo a la integración: todos los strings no vacíos de las filas reales usan este cifrado. En el remoto hay 658; otros 241 strings están vacíos. El decoder conserva los vacíos como datos, en lugar de un sentinel de error de la UI. Rechaza cifrados no vacíos inválidos y cambios de tipo en campos cifrados conocidos. También abre claves nuevas, evitando dejar ciphertexts silenciosos sin procesar.

El asset `assets/config.json` tiene otra representación y no se utilizó como catálogo. No se anuncia soporte de archivos por haberlo encontrado.

## Fuente remota

`AsyncTaskC0819a6` construye su URL mediante `BF(4).toString()`: bytes XOR constantes; la receta guardada en `tools/recover.py` los recupera sin ejecutar código de la APK. Destino exacto `https://raw.githubusercontent.com/nemygoku/genisvpn/refs/heads/main/genis`. GET de HttpURLConnection sin User-Agent propio: backend y receta usan un perfil analítico Dalvik/Android 14, sin afirmar captura de un dispositivo físico ni atestación.

Descarga real: HTTP 200, text/plain; charset=utf-8, 107.480 bytes; SHA256 `0eb4a091e0f522cadb76c1172063bad1e1c136535b7945854fc0fdb88c01aa55`. Catálogo 1114 con 84 servidores. La descarga operativa se repitió y coincidió. No requiere credenciales HTTP, login ni renovación de sesión; no se imitó atestación. El broker limita el destino, revalida DNS público, fija IPv4/TLS y rechaza todas las redirecciones. El worker solo recibe bytes y permanece sin red.

`flags/config.png` es el catálogo incluido v1/1 servidor y `flags/usr.png` es el documento de usuarios incluido v1/1 usuario. Ambos se verificaron completos por separado. No se estableció una fuente remota de usuarios; no se mezcla ese documento estático con el catálogo remoto ni se usa como fallback.

## Prueba independiente e integración

`CatalogOracle.java` usa únicamente JCA para abrir la capa externa y cada campo; produce referencias completas, comparadas con CLI y worker aislado. También genera los fixtures ficticios. No se guardan perfiles reales en Git. `generated/verification.json` conserva conteos, tamaños y hashes sin mostrar credenciales.

Se conectan broker, directorio público, controles individuales, allowlist del worker y contrato de JSON completo del gateway. Piso del catálogo 69 / 65 fichas / 256 formatos, preservando versiones superiores ya configuradas. Icono launcher legacy original: WEBP decodificado a PNG, igualdad de píxeles comprobada. No se redibuja ni se usa el recurso gráfico de conexión `coneccll` como icono de la app.

9 pruebas Python y 161 Node aprobadas. Descarga real Python y worker reales verificados. Node real devuelve `REMOTE_NETWORK_DENIED` en este ejecutor; replay HTTP/DNS con bytes y resultado de worker reales pasa, expresamente identificado como simulado. Transporte Node en VPS, revisión central de licencias, CI obligatorio de evidencias y despliegue permanecen pendientes. No hubo build Android, merge ni publicación.

## Trazabilidad

Todos los scripts utilizados se conservan en tools. `tools/history/` contiene parches de las versiones ejecutadas de set_constants y verify; se aplican al revés a una copia del archivo canónico para reconstruir v1, no son scripts autónomos. Las revisiones finales agregan el inventario de tipos y la conservación privada del resultado del worker. La instalación automática futura no está habilitada ni aprobada.
