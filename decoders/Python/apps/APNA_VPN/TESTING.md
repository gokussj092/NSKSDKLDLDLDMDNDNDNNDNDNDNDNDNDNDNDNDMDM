# APNA VPN 3.9 — validación

## Comprobaciones reales (2026-10-24)

| Documento | Versión | Free_servers | Payloads | Bytes JSON | Java / worker |
|---|---|---|---|---|---|
| Asset del APKS | 289 | 19 | 491 | 210815 | Íntegros iguales |
| GET activo del APK | 456 | 18 | 493 | 208498 | Íntegros iguales |

La comparación Java es byte por byte; la del worker aislado compara el objeto
JSON entero y exige `isPartial=false`. También se ejecutó la CLI real del APKS
y el GET del script autónomo. La validación anterior de recifrado XXTEA del
asset se conserva como evidencia complementaria, sin confundirla con un MAC.

Una descarga adicional agotó el tiempo de espera del proveedor. La respuesta
200 validada no garantiza disponibilidad continua de ese origen externo.
Un GET posterior volvió a entregar 456 / 18 / 493 correctamente.

Cinco vectores independientes coinciden con la función XOR de la biblioteca
ARM64 original en memoria acotada. No se ejecutan JNI, chequeos de identidad,
arranque Android ni operaciones de red dentro del emulador.

```sh
PYTHONPATH=cloud/workers/python:. python -m unittest tests.test_apna_vpn -v
python scripts/apk_analysis/apna_verify.py /privado/janu.json /privado/remoto.enc
python scripts/apk_analysis/apna_verify.py --file /privado/perfil.apnavpn
python scripts/apk_analysis/apna_native_oracle.py /privado/libputils.so
```

El último comando requiere Unicorn y pyelftools solo para análisis, no para
el lector de producción. Las referencias Java requieren JDK 17 o posterior.

## Pruebas automatizadas

12 pruebas APNA cubren catálogos completos, estructuras anidadas, Unicode,
archivos/texto con y sin contraseña de importación, restricciones preservadas,
comparación Java, workers aislados y CLI autónoma. Se comprueban errores de
Base64/hex/cifrado/esquema, JSON duplicado/no finito, profundidad, sustitutos
inválidos, GET fijo/cabeceras/límites/sin redirecciones y salida 0600 sin
sobrescritura. `--text ''` falla localmente sin descargar contenido.

Node verifica icono original, tarjeta pública, metadatos `.apnavpn`, URL y
agente fijos, IP/TLS/redirecciones y el interruptor individual persistente sin
alterar proveedores previamente deshabilitados. Las regresiones del inventario
mantienen C0=240, C8=252, catálogo mínimo=42 y 43 fichas.

Regresión local final: 128 pruebas Python aprobadas, sin omisiones. Incluye
APNA/ANY/Speicers, inventarios, texto y compatibilidad MM/Tx/4U/1F/AC/TRV/Austro.
285 pruebas Node aprobadas y el servidor web compiló correctamente. Incluyen el recorrido
autenticado del broker APNA y rechazan resultados parciales o inconsistentes.

## Límites de la certificación

Falta una exportación `.apnavpn` real y una prueba Android. Las pruebas de
archivos/texto son sintéticas derivadas de DEX/SO; los dos catálogos sí son
reales. No se incluyen APK/SO/DEX, catálogos ni credenciales reales en Git.
Integración de código en PR #99; sin fusión, despliegue VPS o publicación APK.
