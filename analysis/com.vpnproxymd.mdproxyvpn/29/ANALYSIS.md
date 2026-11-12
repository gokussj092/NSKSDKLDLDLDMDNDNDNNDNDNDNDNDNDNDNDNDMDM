# MD PROXY VPN v1.0.8.8 / build29

Identidad real com.vpnproxymd.mdproxyvpn obtenida del AXML, no del nombre comercial ni una versión de una página cacheada. APKPure devolvió404 para XAPK y APK; el sitio del desarrollador enlaza Google Play. Se siguió el enlace público real de descarga APKDog descubierto en su página ARM64. La URL efímera de distribución no se publica. La procedencia de espejo no acredita la firma del editor; se registran hashes y certificado extraído, sin declarar verificación criptográfica completa de la APK.

El distribuidor devolvió Content-Encoding:none y un flujo ZIP exterior mal formado, con longitudes/CRC de envoltorio obsoletos y sin directorio central exterior. zipfile veía solamente el último APK interior. mirror_archive.py conserva bytes originales y recupera cada APK completo usando su EOCD/directorio central propio; comprueba cada CRC interno, límites, nombre APK y consumo completo del flujo. No repara la APK ni ejecuta su código. Esta excepción de adquisición no debilita los guardas de descargas de catálogo. Véase generated/identity.json, inspection.json y herramientas de intake, incluidos intentos fallidos.

JADX completo1.5.6 terminó exit3 con177 errores globales. Solo se valida la cadena de catálogo. Hometab.Companion.a llama Libv2ray.do_; HomeFragment lee assets/configfile.json o KidConfigMM1 y luego ConfigData. ConfigUpdate$configUpdate$1 llama CU/getVerNotes/GFC y reemplaza el mismo ConfigData. Go.Seq carga gojni; libuz no era la biblioteca del método y su pclntab no fue compatible con el inspector. Inspección estática Go y ARM64, sin ejecución ni emulación.

## Método y una sola fuente

check_native.py fija el SHA del SO, CU0x10195c0, decrypt0x1016040 y DO0x10169d0, instrucciones, tamaños y constantes. CU hace GET a https://strongteam.co/api/ultrasystem/ultrav3.txt con **User-Agent MD PROXY VPN** en mayúsculas. El preset antiguo de ultra.py usaba capitalización distinta, por lo que no se copió ciegamente su receta. decrypt retira el carácter índice3, Base64 y Argon2id v19,t3,m8192KiB,p1,key32; AES256GCM nonce12/tag16/AADsalt16. EO/DO/asset no llevan carácter adicional y usan la segunda constante pública. Coinciden con el formato ya probado Ultra59; codec y oráculo se reutilizan sin modificación, con wrapper/identidad/UA propios.

Se rastrearon los consumidores de HomeFragment, modelo ServerList/NetworkList/ConfigData y llamadas Hometab.a para campos protegidos. Se conservan todas las secciones, campos desconocidos, tipos y valores; solo se abren los contextos de getters registrados. Servers y Networks están en **el mismo JSON y la misma descarga**, por lo que no se crean dos peticiones ni se dividen artificialmente. No se añaden archivos o texto MD sin evidencia.

## Verificación real completa

GET original200,1388157bytes; catálogo5.25:40servers,919networks,4976campos/4976sobres únicos. El documento completo coincide entre libsodiumArgon2id+JCA independientes, codecPython y worker aislado; rawText vuelve a producir el mismo JSON, isPartialfalse,847110bytes. Prueba completa246.08s incluye el oráculo y varias lecturas independientes; no es el tiempo de una solicitud del worker. No se aumentan los límites globales del servidor. Asset3.95 se verifica por separado; no sustituye una prueba remota.

El icono original es WebP192×192/32208bytes, se preserva sin conversión. La API declara image/webp solo para este archivo; PNG y sus hashes anteriores siguen iguales. Catálogo79, dos nuevas entradas, sin endpoints en metadatos públicos. No se acredita sesión VPN, disponibilidad permanente ni aprobación de despliegue.
