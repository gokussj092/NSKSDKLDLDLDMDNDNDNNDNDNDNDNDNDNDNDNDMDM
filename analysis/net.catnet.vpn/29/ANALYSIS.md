# CATNET VPN — Play 1.2.7 / build29

El propietario entregó APKS exportado desde Google Play y fechado por él el05nov. La identidad binaria real es net.catnet.vpn /1.2.7 /29, base SHA-256870a4e41f11a1cc3987c2f6b098ffa6adb1f69877820065ab7d938b394b39676. El certificado extraído dcc1eb6396b9c1b8ec554c99bb8a9ca7feda3a00fee05a977ec186571661c90c coincide con el build27 anterior. Se inventaría la huella, sin afirmar comprobación criptográfica completa de firma.

La exportación tiene base.apk y tres splits; prepare_catnet.py registra cada hash sin ejecutar ni instalar APK. La comparación del ZIP base con27 encuentra5 miembros cambiados (manifiesto, DEX, perfiles y fuente MaterialIcons) y239 idénticos. La versión no se infiere del tamaño ni del nombre del archivo.

JADX1.5.6 completo/auto muestra las mismas bases https://pussyvpn.com/xjvpn/ y https://xjdev.net/xjvpn/. MobileApiService conserva app-update y servers; fe.c fija setIntegrityVersionCode(29). Se revisó también ke(3): es paso directo, sin una ruta alternativa oculta. El fallback DNS observado se limita a xjdev.net. No se redirige el servidor a ese host ni se omite el preflight.

Se actualizan las cabeceras/version query a29 desde una constante común por lenguaje. El protocolo de servidores sigue siendo JSON sin cifrado observado; se preserva el codec y la compatibilidad previa. La recuperación limitada de fallos transitorios y el UUID estable por operación se conservan.

Sondeo real29: preflight devuelve503 del transporte/91bytes, con error de conexión antes de cabeceras del origen. No hubo JSON de política ni descarga de servidores. No se puede deducir un nuevo requisito de Integrity ni fallo de cifrado de ese resultado. El estado actual es NETWORK_UNAVAILABLE, sin afirmar restauración. Los6 servidores de la investigación27 pertenecen a otra observación histórica.

Herramientas propias: prepare_catnet.py (intake), compare_builds.py y probe.py. Se reutilizaron el instalador/JAR JADX y el wrapper de decompilación anterior, sin cambios; no se copian APK, DEX, bibliotecas, fuentes del proveedor ni perfiles a Git. Solo metadatos y huellas revisados. No se ejecutó Android ni una conexión VPN.
