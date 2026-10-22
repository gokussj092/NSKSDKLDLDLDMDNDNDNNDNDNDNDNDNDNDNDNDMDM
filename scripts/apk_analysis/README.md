# Herramientas de análisis APK

Fuentes reutilizables para preparar próximas integraciones. No forman parte del
servidor ni se importan desde los decodificadores. No necesitan un APK en runtime.
Se mantienen aquí los scripts y versiones; los binarios se reconstruyen.

Requisitos: Python 3.10+, JDK 17+ y `pip install -r requirements.txt` dentro de un
entorno virtual. JADX **1.5.6** se descarga de su publicación oficial solo con
`--install`; `decompile.py` verifica SHA-256 del ZIP y JAR antes de usarlo.
También acepta un JAR existente con `--jar`, verificando el mismo checksum.

```bash
python scripts/apk_analysis/inspect_apk.py aplicacion.apks scripts/apk_analysis/work/app \
  --asset gremlin.json --native libputils.so
python scripts/apk_analysis/decompile.py --install
python scripts/apk_analysis/decompile.py scripts/apk_analysis/work/app/dex/classes2.dex \
  scripts/apk_analysis/work/jadx2
python scripts/apk_analysis/paranoid_strings.py scripts/apk_analysis/work/jadx2/sources \
  'scripts/apk_analysis/work/jadx2/sources/org/lsposed/lsparanoid/Deobfuscator$MHRTUNNELVPN$app.java' \
  scripts/apk_analysis/work/clear --inventory
python scripts/apk_analysis/random_strings.py fuentes-jadx C1682lA salida-privada
```

- `inspect_apk.py`: metadatos, hashes, DEX raíz, PNG original si existe como PNG,
  assets explícitos y bibliotecas de una ABI. No reconstruye iconos adaptativos.
  Lee ZIP sin `extractall` y rechaza entradas ausentes, duplicadas o excesivas.
- `decompile.py`: llama a JADX con argumentos separados; conserva su código de
  salida y log. Errores de descompilación requieren inspección, no se ignoran.
- `paranoid_strings.py`: reproduce el algoritmo LSParanoid de `RandomHelper` y
  `DeobfuscatorHelper`; admite llamadas con IDs literales. `--inventory` requiere
  un seed compartido. Solo serializa datos UTF-16 a un programa Java conocido:
  no compila clases ni expresiones arbitrarias extraídas del APK.
- `random_strings.py`: patrón de constructor con `long[]` y `java.util.Random`,
  como el confirmado en MegaTunnel. El nombre de clase es obligatorio; no
  presupone que cualquier constructor tenga este algoritmo.

Los patrones son específicos de familias confirmadas; no son un desempaquetador
universal de LIAPP ni garantizan recuperar todo el código protegido. Verificar
la receta y comparar documentos completos con un oracle independiente antes de
registrar un proveedor. Oracles sintéticos reproducibles: `tests/golden/`.

`cache/` y `work/` están ignorados. Mantener APK/APKS, SO/JAR, capturas, inventarios
de cadenas y resultados descifrados fuera de Git. Las salidas pueden contener
claves de formato o datos de usuarios; las herramientas imprimen solo recuentos
y metadatos. La descarga de catálogos se realiza por el lector de cada aplicación,
no por estas herramientas.
