# Aura Net VPN — validación del build 19

## Catálogos reales

| Documento | Versión | Servidores | Redes | Campos cifrados distintos |
|---|---|---|---|---|
| Asset del APKS | 1.01 | 4 | 663 | 40 |
| GET oficial | 2.18 | 14 | 685 | 424 |

Ambos JSON completos, incluidos sus catorce bloques y campos internos,
coinciden con libsodium Argon2id de 8 MiB + AES-GCM del JDK. La referencia
recoge todas las cadenas con forma de envoltura, sin importar la whitelist
del lector. También coinciden los objetos completos de los workers aislados,
con `isPartial=false`. No se imprimen ni se guardan sus credenciales en Git.

Ocho documentos independientes comprobados: seis sintéticos y dos catálogos
reales; 479 campos internos contando 15 de las variantes sintéticas. Las
pruebas de perfiles cubren envoltura export, EO y JSON plano. **Falta un
archivo `.aura` exportado realmente por este build y una prueba Android.**

## Reproducción

```sh
PYTHONPATH=cloud/workers/python:. python -m unittest tests.test_aura_net_vpn -v
python scripts/apk_analysis/aura_net_verify.py \
  --catalog /privado/configfile.json --catalog /privado/remoto.enc --worker
python scripts/apk_analysis/aura_net_verify.py --file /privado/perfil.aura --worker
```

Referencia: libsodium disponible en el sistema y JDK 17+. No requiere APK,
ejecución JNI ni autenticación Android. El runtime del lector usa solamente
`argon2-cffi` y `pycryptodome`; no necesita Java o libsodium.

11 pruebas específicas aprobadas: paridad de documentos completos, bot y
worker, claves y AAD, manipulación de salt/nonce/ciphertext/tag, JSON inválido
autenticado sin fallback, campo interno roto sin fallback, Unicode, tipos,
restricciones, errores/límites/profundidad y compatibilidad histórica con y
sin AAD. El script autónomo funciona fuera del repositorio; resumen sin
credenciales, salida 0600 y rechazo de sobrescritura. Se verifican GET, URL,
agente, timeout, tamaño, codificación, errores y redirecciones.

Regresión adicional: **50 Python** aprobadas (familia Ultra/Sandok, C8, MM,
Tx y APNA) y **290 Node** en toda la web. Incluyen el recorrido autenticado
del broker Aura, coincidencia rawText/structuredJson, rechazo de parciales,
icono original, disponibilidad global e interruptor individual persistente.
Build web correcto. C0=240, C8=252, catálogo mínimo=43 / 44 fichas.

La CLI real descargó el catálogo completo y lo guardó en JSON 0600. La
prueba se ejecutó en Linux con Python y dependencias instaladas; Android y
Termux reales quedan pendientes. No se recompila una APK ni se despliega VPS.
