# Cloud: contraseñas NPVS y Ultra Custom — alcance verificado

## Fuentes
- Archivo adjunto `NPVS_Telegram_Bot_🔓Decryptor_VPN.py` (referencia de versión anterior; **no se agrega ni se despliega**).
- Archivo adjunto `ultra_custom_52.py`; idéntico al blob Git `ca62da9ad7f5cdde299b8cff1aa656e09c5b0a6b` ya existente en `decoders/Python/apps/Ultra_Custom/ultra_custom_52.py`.

## NPVS: soporte de contraseña comprobado (2026-10-22)

El Python canónico ahora admite **passphrase de NPVS v5 compacto**, verificado
con el archivo real y su contraseña aportados por el usuario. La DEK se abre
con PBKDF2-HMAC-SHA256 y ChaCha20-Poly1305, no con el parser antiguo. Se compara
todo el JSON con JDK independiente y worker: 16 registros y nueve campos
`npvs1:` internos, sin recorte. Worker/gateway aceptan `credentials.password`
y `publicKey` para diagnóstico, por stdin y sin HWID. No se cambia la UI Android.

Los dos adjuntos normal/public-key son idénticos NPVS v6 recipient. La public
key coincide pero falta la privada del destinatario; se devuelve
`PRIVATE_KEY_REQUIRED` y no un resultado parcial. Queda pendiente ese modo.
La nueva muestra normal Kurdo v5 app-key 2 ya se abrió sin credenciales, completa
e igual a JDK/worker. Se conservan las tablas/pruebas. El nuevo script de texto
se entrega separado para integración posterior, según la instrucción del usuario.
Ver [la investigación nueva](../NPVS_PROTECTED_FILES.md).

### Limitación documentada antes de esta actualización

El archivo antiguo reconoce un encabezado JSON `passphrase` y usa
`PBKDF2-HMAC-SHA256` con ChaCha20-Poly1305 para abrir una clave del
documento. El decodificador actualmente desplegable de NPVS v5 (`npvs.py`)
usa un encabezado binario compacto firmado y un descriptor `appKey`
distinto. El formato de contraseña de v5 NO queda demostrado por ese código
antiguo y no se debe asumir que ambos formatos son intercambiables.

**No se ha portado el decodificador antiguo**. La muestra v5 real, su contraseña
y la verificación del descriptor se recibieron y completaron el 2026-10-22.
Se mantiene la regla: no convertir un fallo de firma o autenticación de NPVS
en `PASSWORD_REQUIRED`.

## Ultra Custom 5.2: soporte disponible
El códec canónico existente ya reconoce `.ua` y `ua://`, XML Properties,
EXA1/UAB1, UAP1, bundles y wrappers de contraseña. No había que duplicarlo.
Los adaptadores Cloud ahora:
- Ejecutan el códec por formato exacto, sin aplicar de forma oportunista
  claves de otros productos que reutilicen una extensión.
- Admiten `credentials.password` únicamente para `file.format="ua"` o
  textos `ua://`, además de las rutas previamente autorizadas.
- Devuelven `PASSWORD_REQUIRED` y `AUTH_FAILED` desde el subproceso, sin
  devolver bytes del archivo, resultado parcial ni contraseña en esos errores.
- Entregan la contraseña a un proceso aislado por stdin, nunca en argv,
  entorno, URL o telemetría. El límite elegido es 4096 bytes UTF-8.
- La aplicación muestra un diálogo con pantalla segura y texto localizado,
  reintenta sobre los mismos bytes `.ua` en memoria y borra el buffer tras
  completar o cancelar. Los textos `ua://` se reintentan sin almacenarse en
  historial mientras falle el descifrado.
- No cambia el catálogo de Server VPN ni la versión de sus novedades.

## Riesgos y pruebas
- Colisiones de extensión: el nombre de extensión por sí solo no demuestra
  compatibilidad criptográfica; **nunca** realizar fallback indiscriminado
  tras fallar la autenticación del códec.
- Validar los vectores sintéticos versionados de Ultra Custom para perfiles
  sin contraseña, protegidos, bundles, contraseña errónea y enlaces.
- `python -m unittest cloud/workers/python/test_engine.py` desde el entorno
  de ejecución configurado del worker; `cd cloud/web && npm test`.
- Verificar Android Cloud mediante CI, además del comportamiento de diálogos
  protegidos en un dispositivo físico.
- No fusionar ni desplegar el PR #96 automáticamente.
