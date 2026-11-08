# SP-DECODE F7-A5 — perfil experimental JADX Lite y visores Android

Rama: feat/nuevas-integraciones. Público: NO. Beta privada del operador.

## Estado y límites
- VPS objetivo verificado por el operador: Ubuntu, 2 vCPU, 3.7 GiB RAM, 22 GB de disco libres y 0 swap.
- El contenedor existente apk-qa conserva su límite de 320 MB y la recepción/QA HPKE V2.
- No se intentará ejecutar Ghidra headless, Hydra ni fuerza bruta en este perfil.
- `enable-lite` necesita 3.4 millones de KiB de RAM total, 1.1 millones de KiB MemAvailable y 6 millones de KiB libres de disco. Rechaza la activación antes de mutar secretos cuando falta algún recurso.
- El contenedor apk-tools se ejecuta en una red privada (sin puerto del host, sin Docker socket ni secretos HPKE, usuario 65532, sistema read-only). Docker aplica 1152 MB y 0.8 vCPU.
- La JVM JADX usa `-Xmx512m`, un hilo y máximo 180 s. El JAR JADX 1.5.6 se descarga **al construir la imagen** con SHA-256 fijado, no por análisis. No se ejecuta código del APK.
- Para ahorrar disco y CPU, el perfil Lite solo extrae el base.apk para JADX; el receptor original ya ha analizado todos los splits, DEX y bibliotecas ELF por separado. Si JADX genera archivos parcialmente antes de fallar, se etiquetan `PARTIAL_OUTPUT` sin afirmar ejecución completada.
- El volumen `apk-tools-scratch` está respaldado por disco, no RAM. Un directorio temporal independiente se elimina tras cada trabajo. Los residuos de cortes de energía pueden necesitar recuperación de mantenimiento; no se ofrece cuota de disco garantizada por Docker.

## Instalación después de validar CI
~~~bash
sudo spdecode update all feat/nuevas-integraciones
sudo spdecode apk-qa enable
sudo spdecode apk-qa enable-lite
sudo spdecode apk-qa status
~~~
El tercer comando puede tardar en descargar/compilar Java y JADX **solo la primera vez**. Fallos de build o de salud restauran el archivo privado de configuración y detienen el worker experimental. No ejecutar `enable-tools` (perfil de 8 GB).
El APK Android no requiere cuentas/créditos para esta beta, pero los cambios en los visores exigen nueva APK firmada.

## Visor JSON de descifrado y catálogos Server VPN
- Área inicial de hasta 150 líneas lógicas, numeración alineada y documento completo indexado por JNI.
- Búsqueda en todas las líneas indexadas; salto al siguiente resultado y resaltado de la línea. El valor protegido en modo privacidad no se usa como candidato de búsqueda.
- Zoom táctil entre 75 y 210 % de la fuente original. La longitud del documento permanece intacta.
- Pulsación prolongada sobre una línea para elegir y copiar texto del fragmento visible (hasta 2048 columnas); opción de copia completa existente permanece.
- Nada de `Text` gigante para el JSON decodificado. No se modifica el JSON exportado ni el historial.

## Resultados APK
- Informe JSON presentado como bloque de código Markdown `json` con búsqueda nativa, selección y opciones de copia del JSON y del bloque Markdown.
- Si el servidor añade una lista `artifacts` con `content`, `mimeType` y `name`, se crean secciones adicionales sin alterar el informe original. Los tipos reconocidos son application/json, text/markdown y texto genérico.
- Los estados `COMPLETED_PARTIAL`, `jadxExecuted`, `ghidraExecuted` y `vendorMethodValidated` no se falsifican. Analizar DEX no equivale a recuperar sus claves o un método de descifrado válido.

## Pendientes antes de dar por terminada la beta
1. GitHub Actions JNI/Android compile, F7 QA y release firmada deben concluir en verde.
2. Probar el arranque de apk-tools en el VPS de 3.7 GiB; no está disponible aquí acceso SSH al VPS del operador.
3. Enviar un APK/APKS autorizado completo, comprobar memoria y que la salida `analysis.tooling.resourceProfile` sea JADX_LITE cuando el worker realmente se ejecuta.
4. Testear zoom, búsqueda y copia con un JSON de miles de líneas en un Android físico.
5. Para Ghidra sobre ELF grande, ampliar recursos o separar un segundo worker; no eludir la comprobación de 8 GB.

## Precio orientativo OVHcloud publicado (2026-11-07)
Gama VPS 2027, desde: VPS-2 8 GB RAM/4 vCore/75 GB $8.50 USD mensual;
VPS-3 12 GB RAM/6 vCore/100 GB $12.32 USD mensual;
VPS-4 24 GB RAM/8 vCore/200 GB $23.37 USD mensual.
Precio sujeto a impuestos, país, oferta y tipo de contrato existente. Una VPS anterior no se migra automáticamente a la nueva gama.
Fuente oficial: https://www.ovhcloud.com/es/vps/
