# AustroPlus VPN 15.0.1 / build15 — revisión real

La distribución pública actual es xyz.tekidoer.austroplus.vpn /15.0.1 /15. Se conservaron hashes de XAPK, base APK y certificado extraído en generated/identity.json. El certificado fue inventariado, no se comprobó criptográficamente la firma completa del APK. No se ejecutó código del APK.

## Causa y trazado

La fuente anterior AustroPlusVPN.json ya no descarga. Build15 carga res/raw/tekidoer.js mediante w14.k(BaseActivity), lo guarda en DATA de system.db y pa.a() llama gj.f(). gj.f() conserva la constante pública de XXTEA y llama ab.o(): misma disposición little-endian, delta y longitud final que el lector anterior. hg3.c() conserva Base64/XOR de seis bytes. No se cambiaron las primitivas compartidas ec.py ni el oráculo Java.

El catálogo incluido revela el actualizador fijo https://raw.githubusercontent.com/SpkHexX/HexX/refs/heads/main/AustroTunVPN.json. BaseActivity guarda url_updater tras hg3.c; MainActivity lee URL_UPDATER; hz0.a hace GET. El broker utiliza únicamente esta URL revisada: no sigue destinos arbitrarios indicados por una respuesta.

Los registros cambian Name por name y cambian los nombres de campos protegidos. Las rutas MainActivity.V -> hg3.c, MainActivity.t, la/ka y los getters w2 separan campos protegidos de nombres, puertos, modo, banderas y metadatos. El lector admite tanto registros build13 como build15, conservando las claves originales. No convierte tipos ni elimina campos desconocidos.

## Herramientas y evidencias

Se reutilizó el descargador validado de TunnelDoom mediante analysis/_intake/austro-cat-2026-11-09/tools/acquire.py. El wrapper de este build fija package/build; el análisis exige los hashes registrados. Se reutilizó el instalador verificado de JADX1.5.6, invocando el JAR completo con modo auto, 2200MiB y tres hilos. JADX termina3 por errores ajenos a los caminos comprobados; no significa reconstrucción íntegra.

random_strings.py se reutilizó sin cambios para g40/f40 (Java Random / long array): 6203 constantes, 192 fuentes. El Java de f40 conserva el aviso de JADX sobre el salto de eliminación de NUL; el resolver usa el algoritmo propio ya contrastado, sin ejecutar clases del APK. Las fuentes descompiladas se mantuvieron privadas.

inspect_apk.py conserva trazado, hashes y extracción del recurso. inspect_v1.py conserva el primer intento: el descifrador build13 abrió XXTEA pero rechazó el esquema nuevo por los nombres de campos. El ajuste es del esquema y de la fuente, no de una clave inventada. Una primera comparación Java concurrente dio recuento inesperado de líneas de salida; no se aceptó esa ejecución. La repetición secuencial estricta pasó para el catálogo entero.

verify.py aplica el oráculo Java independiente preexistente a la capa completa y a todos los campos protegidos, incluidos vacíos. La igualdad posterior con Python y el worker abarca todo el JSON. make_fixture.py genera únicamente datos ficticios con .invalid, usando XXTEA del oráculo Java, y conserva los negativos de tipos/esquema.

## Alcance

Catálogo remoto real v0.8: 5 servidores y 174 ajustes; catálogo incluido v0.0: 1 y1. Los hashes y conteos de campos están en los proofs. Los archivos y perfiles históricos conservan sus tests; no se recibió una exportación real independiente de build15 ni se certificó su exportador. No se compiló la aplicación ni se desplegó al VPS.

inspect_v1.py corresponde al lector de la base 007984b; con el codec actualizado ya no reproduce el rechazo antiguo. Se conserva la receta histórica, no se ejecuta como prueba negativa del método actual.

Se detectó y corrigió una colisión del nombre inspect.py con el módulo estándar inspect al ejecutar acquire.py junto a Androguard/lxml. Se conservó el inspector como inspect_apk.py; no se instaló ni degradó ninguna dependencia. La lectura de identidad se repitió después de renombrarlo.
