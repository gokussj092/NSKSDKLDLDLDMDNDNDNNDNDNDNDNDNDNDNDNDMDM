# Validación — HTTP FenixVPN 19.4

## Fuente analizada

- Paquete: `com.fenix.vpn`; versionName `19.4`; versionCode `181`.
- ZIP proporcionado: 61044202 bytes; SHA-256
  `9095c8f837bc97dfff79d48dadc5ee319f4547c9999964bf5e7edd47d7adacb4`.
- `base.apk`: 54773646 bytes; SHA-256
  `a6a4ce1c56853b6cd5015434dd211c6ac72064838c74c0a00c67e6962596efa9`.
- Icono del recurso de aplicación `0x7f080117`, resuelto en
  `split_config.xhdpi.apk:res/drawable-xhdpi-v4/ic_launcher.png`:
  **431 × 426**, **89926 bytes**, SHA-256
  `bff1df78ea9249243edb055e86f75d23b31412045c7fdd809a4bfbd2d615ddd1`.
  PNG íntegro, sin redimensionar ni sustituir la marca.

## Catálogos reales

Solo se realizaron los GET originales recuperados del APK. No se iniciaron
sesiones ni conexiones VPN. Las respuestas y los resultados completos se
mantienen fuera del repositorio y del paquete distribuido.

| Fuente | Bytes cifrados | Perfiles | Campos no vacíos descifrados | Paridad JSON completa |
| --- | ---: | ---: | ---: | --- |
| `assets/flags/config.png` | 1216 | 1 servidor | 8 | Sí |
| `assets/flags/usr.png` | 556 | 1 usuario | 6 | Sí |
| Servidores remotos, HTTP 200 | 386584 | 300 servidores | 2127 | Sí |
| Usuarios remotos, HTTP 200 | 576 | 1 usuario | 6 | Sí |

Hashes SHA-256 de las respuestas cifradas:

- Servidores locales: `bc2bf0ef60ad6593198dcba7db2e6af0ff5bf6e492e77b3fb8d59bdb7f9600b9`.
- Usuarios locales: `7decd9b374d8b1e4b341bec3dfc72aa0fac1780192c79d0f8afd25ea2ce76840`.
- Servidores remotos: `2b680cfa4d8c8fb0dd290adb738722fdc5272795b64f7902b4d32f8ded821f5a`.
- Usuarios remotos: `fd35b93b163e5280d159934d1c5765fdc189f7a9c0d20fc960449515cadfc73f`.

Las clases originales de constantes se ejecutaron con Java para recuperar las
dos URL de descarga, las claves y las rutas. El oráculo ejecuta los métodos
recuperados de `AbstractC6343` (sobre MD5/AES) y `C6334` (rotación). El envoltorio
de campos usa Base64 del JDK en lugar de Android y la misma operación CBC.
Se compararon objetos JSON completos, todas sus listas y tipos; los campos
opcionales vacíos se conservan sin invocar el indicador de error del APK.

## Archivos y fixtures públicos

`tests/golden/fenix_oracle.java` y `fenix_vectors.json` contienen exclusivamente
datos ficticios. Las recetas GCM/DES se reconstruyeron a partir del importador;
GCM usa `GCMParameterSpec(128, nonce)` en Java estándar, equivalente al parámetro
Android del APK. **No son exportaciones reales independientes** y no acreditan
que el botón de exportar funcione en esta versión.

Se comprueban GCM, DES binario, todas las claves conocidas del catálogo, JSON
completo, rotación UTF-16, texto plano de nombres de usuario, duplicados XML,
valores vacíos, Unicode, multilineales y campos desconocidos. También se prueba
la frontera real de subprocesos del worker y la selección del motor histórico
SocksIP sin alterar su salida.

Casos negativos: clave/tag GCM modificados, sobre/IV/sal truncados, CBC y
Base64 incompatibles, JSON duplicado/no finito, listas incorrectas, profundidad,
límites de entrada/salida, entidades XML, HTML remoto y redirecciones. Los
errores no incluyen entradas ni credenciales y no generan JSON parcial.

```bash
python -m unittest tests.test_http_fenixvpn -v
```

Las pruebas automatizadas no consultan los servicios reales. La cantidad de
servidores observada es una evidencia fechada, no una expectativa fija de CI.


## Resultado de la entrega

- Suite principal Python: **664 pruebas**, **9 omisiones existentes**; satisfactoria.
- Worker: **11**; VPS/QA: **39**; gates Cloud: **4**; satisfactorias.
- Web Node: **71**; compilación `npm run build`: satisfactoria.
- **14 controles nuevos** de HTTP FenixVPN; vectores Java y selección SocksIP
  incluidos. Los avisos históricos C2 de HTTP Tweak y decoración SSH se
  conservaron; no se reescribió ningún snapshot.
- CLI con GET real para servidores y usuarios: igualdad JSON completa con Java.
- Catálogo real de 300 servidores a través del subproceso aislado: igualdad
  completa y `isPartial=false`.

No se compiló Android, no se desplegó y no se publicó un APK. La validación de
archivos sigue limitada a recetas del APK y muestras sintéticas.
