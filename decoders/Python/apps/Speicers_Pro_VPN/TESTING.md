# Revisión build123 — 2026-11-01

```sh
python -m unittest tests.test_speicers_pro tests.test_speicers_spcf1 \
  tests.test_http_fenixvpn tests.test_cloud_c8_vpn_registry -v
python scripts/apk_analysis/speicers_verify.py /privado/config-SPCF1.png \
  /privado/config-glifos.json /privado/respuesta-historica.enc
```

35 pruebas Python aprobadas,0 skips. Seis nuevas prueban firmas antes de KDF,
GCM, parámetros firmados, path fijo, dos GET, cabeceras, límites, hash/tamaño/
versión/conteo y ausencia de fallback al feed histórico. Clave RSA de los tests
creada en memoria, solo sintética; no se guarda ni es la del proveedor.
La variante SPCF1 requiere JDK17 y JAR oficial JADX1.5.6 con hash fijado,
instalado por `scripts/apk_analysis/decompile.py --install`, para Gson.
JCA verifica firma auténtica y AEAD del incluido, no importa el codec Python.
El verificador compara recursivamente todo el JSON con tipos y worker aislado.

Tres entradas reales verificadas: incluido123 v1/73 servidores/799 campos,
secundario v9/32 y remoto histórico120 v35/74/797. La CLI --apk123 y --input
histórico produjeron JSON completos privados0600. Ninguna es el feed remoto123.
**La descarga123 sigue pendiente:** timeout antes de HTTP en el manifiesto;
pruebas controladas no se anuncian como éxito real. No se cambia el broker,
catálogo público o Unlocked. No hay `.sks` real123 ni Android físico.
Véase ANALYSIS.md para hashes, cabeceras y evidencia del bloqueo.

---

# Validación y límites

2026-10-24: comparación JSON **completa**, sin guardar datos privados en Git.

| Fuente | Versión | Registros | Campos protegidos, incluidos vacíos | JDK/worker |
|---|---:|---:|---:|---|
| Asset principal real | 36 | 75 | 808 (620 no vacíos) | Iguales |
| Respuesta remota real | 35 | 74 | 797 (609 no vacíos) | Iguales |
| Asset secundario real | 9 | 32 | 0, interior en claro | Iguales |

Se contrastaron envolturas, todos los campos conocidos, listas y metadatos.
Oracle independiente JDK `tests/golden/speicers_oracle.java`; biblioteca AES
distinta de PyCryptodome y rotación mediante Character sobre char Java.
`speicers_verify.py` compara el documento completo con el JDK y el bridge,
imprimiendo únicamente versión, conteos y paridad. Las respuestas de servidores
se guardan de forma privada para verificar; no forman parte de los fixtures.

```bash
python -m unittest tests.test_speicers_pro tests.test_http_fenixvpn tests.test_cloud_c8_vpn_registry -v
cd cloud/web
node --test tests/server-vpn-any-speicers.test.mjs tests/server-vpn-catalog.test.mjs tests/server-vpn-provider.test.mjs tests/server-vpn-version-sync.test.mjs
```

14 pruebas nuevas de Python y 15 regresiones existentes: **29 aprobadas**.
Incluyen worker aislado real, resultados íntegros, filas deshabilitadas,
booleanos, datos desconocidos, límites, JSON duplicado/no finito/profundidad,
campos protegidos inválidos, glifos/UTF-8/encabezados, redirecciones, CLI
independiente con permiso 0600 y rechazo de sobrescritura. Dos catálogos
sintéticos adicionales coinciden con JDK, incluido un campo con letras Unicode
BMP/suplementarias y emoji. Los dos formatos `.sks` reutilizan los vectores
GCM y DES generados por JDK de Fenix: XML, duplicados, vacíos y flags íntegros.

La validación inicial tuvo 52 pruebas Node. El usuario posteriormente solicitó
la incorporación pública junto con ANY VPN; el test de exclusión se sustituyó
por `server-vpn-any-speicers.test.mjs`. La validación actual tiene 60 pruebas
Node, verifica ambas tarjetas, PNG originales, versión 41 / 42 fichas, broker
fijo y switches individuales persistentes. Ver TESTING.md de ANY_VPN.

La CLI autónoma copiada fuera del repositorio descargó y guardó de nuevo el
catálogo remoto 35/74. No se ejecutó en Termux/Android: la compatibilidad se basa
en Python estándar + PyCryptodome, sin APIs de escritorio, ADB o privilegios.

El primer intento con el Python global falló en el worker por dependencias
instaladas solo en el HOME del host. Se repitió con venv y dependencias reales;
el worker cambia HOME deliberadamente. No se cambió código productivo por ese
problema de entorno. Dependencias adicionales de regresión: msgpack y argon2-cffi.

Pendiente: exportación `.sks` real y prueba de la interfaz Android. No se afirma
despliegue, importación en un teléfono ni autenticidad por MAC para catálogos
CBC. La exclusión inicial quedó sustituida por la solicitud posterior de
mostrar Speicers en el catálogo; no se realizó un despliegue automáticamente.
