# Validación HTTP Door 5.0

```sh
PYTHONPATH=cloud/workers/python:. python -m unittest \
  tests.test_http_door tests.test_creeb_injector \
  tests.test_cloud_c8_vpn_registry tests.test_cloud_c8_worker_integration -v
cd cloud/web
node --test tests/file-formats.test.mjs tests/bd-net-vpn.test.mjs tests/c12-provider-controls.test.mjs
```

**27 pruebas Python y 22 Node aprobadas**, sin omisiones. Python incluye siete
pruebas nuevas de HTTP Door, nueve de CREEB (parser compartido), un gate C8 y
diez integraciones previas. Node cubre el formato público, respuesta de
metadatos 44→45, ausencia de proveedor inventado y controles persistentes.
`validate_project.py`, generador de formatos y `git diff --check` correctos.
No se requiere un nuevo build web por cambiar datos y versión del catálogo.

Tres documentos sintéticos completos generados por el JDK independiente:

1. Perfil sin protección y credenciales de túnel sintéticas.
2. Perfil protegido con fecha, HWID, operador, root y campos desconocidos.
3. Entradas duplicadas, vacío, clave vacía, saltos CR/LF, Unicode BMP y dos
   pares sustitutos numéricos para emoji.

`http_door_oracle.java` usa DESKeySpec, SecretKeyFactory y el nombre `DES`
observado en el APK. Cifra, vuelve a descifrar y compara Properties Java.
Los tres ciphertext se abren con el lector, CLI, worker aislado y HTTP interno
autorizado: igualdad del JSON entero, rawText/structuredJson e isPartial=false.
Se compara todo el XML en bytes, el mapa efectivo y las entradas ordenadas.

El bundle generado se ejecuta fuera del repo sin PYTHONPATH y sin sus carpetas
hermanas. Archivo y stdin coinciden completos para los tres casos. Guardado
0600 y rechazo de sobrescritura comprobados; errores sin datos de entrada.
Padding, ciphertext truncado, otras envolturas, límites, entidades/DTD ajenos,
XML incorrecto, referencias sustitutas aisladas y UTF-8 inválido fallan.

Para verificar una futura muestra privada real, sin escribir su contenido:

```sh
python scripts/apk_analysis/http_door_verify.py /privado/perfil.kyz --worker
```

Este verificador compara JDK, XML en bytes, Properties y resultado entero del
worker. **No se recibió una exportación `.kyz` real; Android y Termux reales
siguen pendientes.** No se probó descarga de servidores: no se identificó
origen de catálogo y la CLI no contiene red. DES no aporta autenticación MAC.
