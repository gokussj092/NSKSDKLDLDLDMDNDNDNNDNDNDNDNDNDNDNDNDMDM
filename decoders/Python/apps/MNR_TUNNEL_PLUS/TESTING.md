# Validación MNR TUNNEL PLUS

```sh
PYTHONPATH=cloud/workers/python:. python -m unittest tests.test_mnr_tunnel_plus \
  tests.test_http_door tests.test_cloud_c8_vpn_registry tests.test_cloud_c8_worker_integration \
  tests.test_cloud_c0_inventory tests.test_android_a24_catalog tests.test_cloud_c2_text -v
PYTHONPATH=cloud/workers/python:. python -m unittest tests.test_cloud_c8_android_input_routes -v
python scripts/apk_analysis/mnr_verify.py /privado/asset.enc /privado/remoto.enc --worker
python scripts/apk_analysis/mnr_verify.py /privado/perfil.stp --profile --worker
python scripts/cloud_c0_inventory.py --check
python scripts/android_a24_catalog.py
python scripts/cloud_formats_catalog.py
cd cloud/web
npm test
npm run build
```

**50 Python y 309 Node aprobadas**, sin omisiones; build web correcto con el
endpoint nuevo. Nueve pruebas Python MNR; siete HTTP Door, diez worker C8,
un gate registro C8, 16 gates C0/Android, tres texto y cuatro de enrutamiento
Android Cloud. En Node, 13 MNR
(nueve casos principales y cuatro subcasos) dentro de toda la web. Tras el
ajuste de métricas, 32 casos MNR/C3.5 volvieron a aprobar. Generadores y
git diff --check correctos. No se cambia matriz, assets ni diseño Android.
CloudTextFormats reconoce el enlace ID10 y ciphertext del alfabeto MNR, sin
claves o descifrado local. Se añadió un caso instrumentado para positivos,
referencias inválidas y ausencia de diálogo de contraseña; **no se ejecutó en
dispositivo local**, queda para Android CI/móvil. No se entrega APK nuevo.

Referencias independientes:

- JDK mnr_oracle.java: AES/CBC/PKCS5Padding, SHA256 del HEX UTF8, ambos alfabetos
  y tres constantes. Cifra vectores sintéticos y abre catálogos reales. El
  esquema de campos del verificador es independiente del módulo productivo.
- Dos catálogos reales completos iguales a Java y worker: 537+612 campos
  cifrados. Todos los nombres, flags, desconocidos y listas conservados.
- Un catálogo sintético con los 21 campos, booleanos con nombres engañosos,
  IDs hex, vacío/Unicode y un campo desconocido cifrado que se conserva.
- Dos perfiles sintéticos completos, local y cloud, con/sin contraseña y con
  HWID/fecha. Igualdad JDK, archivo, clipboard, CLI y worker aislado.
- CLI sola fuera del repo sin PYTHONPATH, archivos 0600 y no sobrescritura.
  GET real sin argumentos, JSON completo igual a captura 14.4/14/119. APKS
  real abierto offline 1.0/9/112. No son pruebas de un Termux físico.

Transporte online sintético: sesión antes de red, consentimiento en endpoint
dedicado, texto con prefijo explícito, metadata→primer token→cuerpo completo,
normalización del objeto Firebase, bucket/name/token estrictos, cuotas,
interruptor persistente, TLS/DNS pública fijada, rechazo de redirect,
compresión, exceso, esquema/JSON ambiguo y resultados parciales/inconsistentes.
Se verifica el broker real con transporte simulado; no se sustituye esa
evidencia por una supuesta importación live. No se escribe en Firebase.

La ruta HTTP devuelve REMOTE_CONFIG_UNAVAILABLE para 404/410; permisos o red
no se presentan como contraseña equivocada. Sin tokens/referencias/cuerpos
en errores o métricas. CBC no autentica: padding/esquema no son un MAC.

**Pendientes:** export real `.stp`, enlace online real, permisos del bucket y
Android/Termux físicos. `.sft` no se publica por un helper sin ruta activa.
La prueba `--profile` del verificador queda lista para la muestra futura.
