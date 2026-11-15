# LITRON VPN — com.fleet.vpn /3.5.9 /25

El propietario aportó spdecode_litronvpn.py y un icono para Litron VPN. Se preservó el script sin modificar, SHA-256070dd4a959ef438e1bab065d59f2eb0443a1483a1e0ae961327357f8c8107fd5, tras leerlo completamente. Su instalador pip y media-scan no se ejecutaron: solo se llamaron las funciones puras con PyCryptodome ya disponible. El runtime integrado usa dependencias explícitas y jamás instala paquetes durante una descarga.

La identidad base se contrastó con la ficha oficial https://play.google.com/store/apps/details?id=com.fleet.vpn y con el APK público adquirido,3.5.9/build25, hashes en generated/identity.json. Litron Pro tiene otra ficha/paquete (https://play.google.com/store/apps/details?id=com.litron.udp); queda pendiente como investigación separada. No se adquiere su APK ni se reutilizan para ella la fuente, el icono o el método de la app base.

## Trazado y formato

lh0.c carga assets/config/config.json o Config.json y llama q.f con la constante pública godtech25. vagol usa GET de https://godtechprime.github.io/latestv2ray.txt. q.d convierte los bytes de la constante a HEX ASCII mayúsculas; q.l aplica SHA-256 para clave256. q.f abre Base64/ciphertext con AES-CBC, IV16 ceros y PKCS7. El alfabeto de q.g es U+2000..U+200F y cada par representa un byte. Nunca se recorta ni normaliza el carrier: parte del alfabeto es espacio Unicode.

MainActivity.F2 se construye con nueve desplazamientos unsigned de constantes Java. inspect_apk.py evalúa solo esa aritmética y confirma que la entrada pública para campos coincide con la de catálogo. Las llamadas q.f(F2, ...) abren campos; todos los40 campos ocultos de la muestra remota fueron Base64/AES-CBC. El helper del propietario entiende además raw AES y texto UTF-8 empaquetado, cubiertos solo por fixtures sintéticos donde no hubo evidencia real.

CBC no autentica datos. El reencriptado determinista del script comprueba reversibilidad, no origen ni ausencia de manipulación. La integración exige padding, UTF-8, JSON y esquema válidos, duplicados/no finitos/profundidad/tamaño; los errores no entregan un JSON truncado. Las claves, tipos, listas, campos desconocidos y cadenas JSON permanecen completos. No se añaden las claves editoriales de créditos del script a los datos del catálogo del servidor.

## Evidencia y herramientas

JADX completo1.5.6, auto/no-res/j3/Xmx2200m: salida3 por métodos ajenos, no reconstrucción total. La inspección solo lee fuentes y hashes. El catálogo remoto fue HTTP200,444168bytes; v289,8 servidores/86 redes. El asset real v12 contiene5/5. Se comparó el JSON íntegro con un oráculo propio Java/JCA independiente, el helper original, Python y el worker aislado, incluyendo40/20 campos ocultos.

El icono aportado se conserva byte por byte:288×288,86055bytes, SHA-25638a931316e6ea65793f377eccd66924790a3ff273d250d8955b6b48a7867aae0. Se documenta como aportado por el propietario; no se presenta como extracción del APK.

Solo catálogo base. No hay archivos, texto, exportación, desbloqueo ni compatibilidad Pro certificados. No se ejecuta APK/SO ni se inicia VPN. La firma criptográfica completa del APK y pruebas Android/VPS quedan fuera del resultado validado.
