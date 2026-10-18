## Pruebas reales antes de publicar en Google Play: Cloud QA

**No se necesita publicar la APK, registrar una versión en Play Console ni generar un token de Play Integrity para ejecutar pruebas privadas de los descifradores.** Esta modalidad es independiente y no cambia el comportamiento de las compilaciones públicas.

Después de actualizar ambos contenedores a la rama de QA:

```bash
sudo spdecode update all feat/cloud-c8-vps-installer-updater
sudo spdecode qa start
```

**Alternativa para generar la APK de pruebas en un VPS x86_64 con SDK instalado y tu misma clave de firma configurada:**

```bash
sudo spdecode android build --version-name 1.2.2 --version-code 28 --testing-only --qa
sudo spdecode android artifacts
```

La bandera `--qa` solo se acepta dentro del canal `--testing-only`; la compilación ordinaria permanece sujeta a Play Integrity y no habilita la pantalla QA.

El segundo comando:
- Verifica que existan el secreto del worker, el de sesiones y el proxy HTTPS confiable.
- Activa temporalmente la API de descifrado, quita temporalmente el bloqueo de mantenimiento y habilita el canal QA **por solo cuatro horas**.
- Genera un código aleatorio de gran entropía (`spqa-...`), lo guarda exclusivamente como HMAC-SHA256 con caducidad en Redis y lo **muestra una vez en la consola privada del VPS**.
- Recrea únicamente la web API y prueba la disponibilidad real del worker. Si falla, restaura la configuración anterior.
- Preserva el estado anterior de los interruptores de API y mantenimiento para restaurarlo al detener QA.

En el teléfono instala la APK firmada **SP-DECODE Cloud v1.2.2-qa (versionCode 28)**, creada específicamente con `SPDECODE_CLOUD_QA_BUILD=true` y URL `https://api.spdecode.xyz`. Ve a **Ajustes > Cloud QA · Pruebas privadas** dentro de la aplicación principal, introduce el código temporal y pulsa **Activar acceso QA**. Esta sección se añade únicamente a la copia de Ajustes compilada para QA; los archivos originales de interfaz del repositorio permanecen intactos. El segundo icono **SP-DECODE QA** también sigue disponible como acceso alternativo. Después descifra archivos y textos como siempre. El resultado continúa llegando del worker aislado y alimenta las estadísticas por extensión; la aplicación no incorpora ningún motor local ni secretos permanentes del servidor.

El cliente envía el código una vez por sesión al endpoint `POST /api/v1/session/qa` después de obtener un desafío ligado al origen de la solicitud. Las sesiones se firman con el mismo mecanismo del backend, vencen a los cinco minutos como máximo, están limitadas en frecuencia, y dejan de funcionar inmediatamente cuando se desactiva QA. El código **no se compila ni guarda en la APK**, no se persiste en el dispositivo y no puede utilizarse desde la aplicación pública porque el icono QA queda deshabilitado y el servidor solo admite el canal durante una ventana de pruebas.

## Habilitar NUR Server VPN y proveedores remotos durante QA

El servicio **Server VPN / NUR Tunnel** no necesita cambios en Android: el cliente ya usa
`/api/v1/decode/import/catalog/remote`. El backend lo mantiene desactivado hasta que
`CLOUD_NUR_FETCH_ENABLED=true` y `CLOUD_NUR_CATALOG_URL` pasa la validación HTTPS.
El repositorio contiene el catálogo de URL de la aplicación legado; este valor se instala
solo en el archivo privado del VPS, jamás se envía como parte de las respuestas ni se
imprime en consola.

Para una sesión QA **ya iniciada**, sin invalidar el código actual:

```bash
sudo spdecode update web feat/cloud-c8-vps-installer-updater
sudo spdecode qa services
sudo spdecode qa status
sudo spdecode qa probe-nur
curl -fsS https://api.spdecode.xyz/api/v1/capabilities
```

El comando `qa services` activa el catálogo remoto NUR a partir de la URL ya validada,
habilita HTTP Injector Cloud **únicamente si** las dos claves reales de ese proveedor
ya existen en `/etc/spdecode/cloud.env`, reinicia solo el servicio web y conserva
el código temporal QA. Si faltan las claves HTTP Injector, el estado indica
`NOT CONFIGURED`; no se inventan claves. La activación es temporal: `qa stop`
restaura las opciones previas.

Si vas a iniciar una **nueva** sesión QA después de actualizar esta rama,
`sudo spdecode qa start` habilita automáticamente los proveedores que estén
configurados correctamente. No requiere `qa services` adicional.

Las capacidades devuelven `nurRemoteEnabled: true` cuando la URL y el interruptor
NUR están configurados, y `cloudImportsEnabled: true` cuando lo está EHI Cloud.
**Esas banderas no prueban que el proveedor remoto esté disponible o que su catálogo
se pueda descifrar:** la prueba final exige pulsar Servidores VPN en un dispositivo
QA autenticado y confirmar el resultado JSON completo. Si falla, consulta
`sudo spdecode logs api` sin copiar ni publicar tokens.

Para cerrar el acceso y revocar el código:

```bash
sudo spdecode qa stop
curl -i https://api.spdecode.xyz/api/v1/ready
```

Para comprobar el plazo sin mostrar el código: `sudo spdecode qa status`. **No publiques ni compartas el código QA, ni una APK de QA vinculada a un código activo.** Este canal está dirigido exclusivamente al propietario/testers autorizados; los controles de Play Integrity y licencia seguirán siendo obligatorios en la modalidad pública. Si se reinicia Redis, se pierde el código temporal y se debe detener QA y emitir otro. Una vez transcurridas cuatro horas, QA deja de funcionar incluso si no ejecutas `stop`; conviene detenerlo igualmente para restaurar mantenimiento y el estado previo de la API.

---
## Corregir los 404 del panel y activar informes administrativos

Las páginas `/features`, `/docs`, `/privacy`, `/status` y la ruta JSON de estado público `/api/site/status` ya existen en Next.js, pero la lista de ubicaciones de Nginx del subdominio `panel.spdecode.xyz` las rechazaba con 404. El generador actualizado las habilita explícitamente sin abrir la API Android `/api/v1/*` ni exponer rutas administrativas en `spdecode.xyz`.

**Actualización de una instalación existente (no restablece usuario ni contraseña):**

```bash
sudo spdecode update web feat/cloud-c8-vps-installer-updater
sudo spdecode panel sync-routes
```

El primer comando construye y reinicia Next.js e instala la CLI actualizada. El segundo reconstruye únicamente el virtual host de SP-DECODE usando los dominios existentes, guarda un respaldo con permisos root en `/etc/spdecode/backups`, comprueba `nginx -t`, recarga y restaura el respaldo si Nginx falla. **No uses `panel reset-admin` para esta actualización:** eso rotaría las credenciales innecesariamente.

**Pantallas:**

| Sección | Ruta |
| --- | --- |
| Resumen y mantenimiento | `https://panel.spdecode.xyz/admin` |
| Estadísticas por extensión, consumo de entrada y actividad diaria | `https://panel.spdecode.xyz/admin/analytics` |
| Fallos por extensión y códigos de error de los motores | `https://panel.spdecode.xyz/admin/reports` |
| Infraestructura y control de mantenimiento | `https://panel.spdecode.xyz/admin/system` |
| Funciones públicas | `https://panel.spdecode.xyz/features` |
| Documentación pública | `https://panel.spdecode.xyz/docs` |
| Privacidad pública | `https://panel.spdecode.xyz/privacy` |
| Estado público | `https://panel.spdecode.xyz/status` |

La telemetría privada, accesible solo después de iniciar sesión y sin caché, agrega conteos diarios en Redis por extensión, éxitos, fallos, código de error y bytes de entrada del worker. Permite rango UTC de hoy o últimos siete días, con retención de ocho días. La instrumentación comienza desde su despliegue: no hay datos históricos por extensión de antes de esta versión. No registra contenido cifrado ni descifrado, nombres de archivos, IPs, credenciales, claves o mensajes de excepción. Los errores de formatos desconocidos se agrupan en `other` y los códigos no reconocidos en `OTHER_ERROR` para limitar la cardinalidad. No representa consumo de CPU/RAM de Docker ni el tráfico de red completo.

**Límite actual de persistencia:** la configuración C8 de Redis no utiliza AOF ni snapshots persistentes. Por tanto, un reinicio o recreación de Redis puede borrar los contadores antes de los ocho días; este panel proporciona observabilidad operativa temporal, no auditoría histórica permanente. Para métricas persistentes necesitará un almacén separado y migración explícita de infraestructura.\n\nLa API de descifrado continúa cerrada bajo los requisitos existentes de Play Integrity, credenciales y mantenimiento; mostrar un panel sin datos no equivale a un fallo de la interfaz. Prueba que `/api/admin/reports` devuelve HTTP 401 sin sesión autenticada y HTTP 200 con una cookie válida.

---

## Restablecer el administrador si el formulario rechaza las credenciales

El estado HTTP 401 de una sesión sin cookie **no** confirma que el usuario/contraseña sean correctos. El comando `reset-admin` incorpora una comprobación real de login HTTPS y sesión autenticada antes de mostrar las credenciales.

En el VPS ya instalado:

```bash
sudo spdecode update web feat/cloud-c8-vps-installer-updater
sudo spdecode panel reset-admin
```

**No vuelvas a ejecutar el instalador completo.** El segundo comando sustituye al único usuario administrador actual por uno nuevo, genera automáticamente usuario y contraseña de alta entropía, almacena solo el hash scrypt en `/etc/spdecode/cloud.env` (permisos 0600), rota la clave de sesión y recrea **solo** el contenedor web. Los usuarios antiguos y sus cookies dejan de servir; no existen registros de usuarios en una base de datos que deban borrarse.

El comando vuelve a generar los virtual hosts SP-DECODE con el origen HTTPS del panel, valida `nginx -t`, recarga Nginx y comprueba `adminSettings().enabled` dentro del contenedor. Después envía las credenciales recién generadas a `https://panel.spdecode.xyz/api/admin/login` **por HTTPS contra el Nginx del VPS** y exige un HTTP 200; finalmente utiliza la cookie de esa respuesta para comprobar que `/api/admin/session` también devuelve HTTP 200. Solo entonces muestra en el terminal:

```text
ADMINISTRADOR RESTABLECIDO — LOGIN HTTPS VALIDADO
URL: https://panel.spdecode.xyz/admin/login
USUARIO: admin_...
CONTRASEÑA: ... (generada en el VPS)
```

Guarda las credenciales localmente en un gestor de contraseñas. **No compartas la salida del comando ni la contraseña** en tickets, GitHub o capturas. El script nunca envía las credenciales como argumentos de procesos ni las escribe en el repositorio. Si la comprobación falla, **no imprime credenciales que no funcionan** e intenta restablecer la configuración anterior y el contenedor; diagnostica la conectividad local, certificado TLS, Nginx, Docker o Redis antes de reintentarlo.

La validación anterior confirma el login por Nginx *desde el VPS*. El acceso desde un navegador remoto depende además del DNS y de la conectividad externa. No es necesario activar `CLOUD_API_ENABLED` ni desactivar mantenimiento del descifrador. Si repetiste muchas veces el login, el restablecimiento limpia únicamente el contador global de intentos administrativos (no sesiones de usuarios Android).

---

## Solución: usuario correcto pero el panel responde ADMIN_DISABLED (503)

En la primera versión de C8, `spdecode panel enable` almacenaba el usuario y el hash de contraseña en `/etc/spdecode/cloud.env`, pero `cloud/compose.yaml` omitía pasar `CLOUD_ADMIN_USERNAME` al contenedor Next.js. Por eso una cuenta válida podía recibir `ADMIN_DISABLED` aunque el instalador declarara que el panel estaba habilitado.

**Corregido:** Compose ahora reenvía el usuario al backend y `spdecode panel enable` comprueba la configuración efectiva dentro del contenedor y que `/api/admin/session` responda `401` a invitados (y no `503`). La sesión no verifica IP.

Si **ya creaste** el usuario y la contraseña, no tienes que repetirlos ni generar secretos nuevos:

```bash
cd ~/SP-DECODE
git pull --ff-only origin feat/cloud-c8-vps-installer-updater
sudo spdecode update web feat/cloud-c8-vps-installer-updater
sudo spdecode panel check
```

El segundo comando reconstruye y sustituye Next.js con el nuevo Compose, preservando las credenciales configuradas. El último deberá mostrar `Panel login backend active (guest session correctly returns 401)`. Si indica `ADMIN_DISABLED`, no compartas `cloud.env` ni contraseñas: usa `sudo docker logs --tail 40 spdecode-web-1` o el diagnóstico sin secretos.

Prueba desde el navegador en `https://panel.spdecode.xyz/admin/login` con el usuario exacto configurado, que distingue mayúsculas/minúsculas. Si se utilizó repetidamente una contraseña incorrecta, Redis aplica limitación temporal de intentos.

## Inicio de sesión desde cualquier red, sin verificación de IP

El panel **no pide ni valida una dirección IP** y no existe ninguna allowlist de IP en Nginx. Para abrirlo desde una red móvil, Wi-Fi o VPN, utiliza **usuario y contraseña** en `https://panel.spdecode.xyz/admin/login`. Una sesión válida se mantiene al cambiar de red hasta expirar o cerrar sesión. La página de entrada es pública, mientras que las rutas `/api/admin/*` exigen una cookie firmada protegida por HTTPS; también se mantienen limitación de intentos y protección CSRF.

Después de instalar C8 o de actualizar una instalación anterior:

```bash
sudo spdecode update web feat/cloud-c8-vps-installer-updater
sudo spdecode panel enable
```

El primer comando reconstruye Next.js con el formulario y las verificaciones actualizadas. El segundo pregunta por usuario, contraseña y confirmación, configura la cuenta en `/etc/spdecode/cloud.env` sin exponer la contraseña ni registrarla en Git, elimina las reglas anteriores de filtrado IP de Nginx y prueba la nueva configuración antes de recargarla. Solo activa **el panel**: la API de descifrado sigue cerrada por mantenimiento.

No reinicies Certbot ni reconstruyas el APK; la autenticación administrativa es completamente del servidor. Para deshabilitar más tarde, `sudo spdecode panel disable`.

# C8 — SP-DECODE Cloud: instalación VPS, actualizador y compilador APK/AAB

**Rama:** `feat/cloud-c8-vps-installer-updater`, basada en C7 (#93). Es software para instalar en tu VPS: **no se ha conectado ni desplegado en una VPS real**. C8 no cambia el bot Python ni las pantallas Android.

## Diagnóstico de panel 502 y API no habilitada

Después de que Docker indique `spdecode-decoder-worker-1 Healthy` y `spdecode-redis-1 Healthy`, Next.js puede permanecer temporalmente en `health: starting`. Un `curl (56) Connection reset by peer` durante esos primeros segundos no equivale a un fallo permanente.

```bash
cd ~/SP-DECODE
git pull --ff-only origin feat/cloud-c8-vps-installer-updater
sudo bash cloud/infra/vps/diagnose-routing.sh
```

Este comprobador **no modifica servicios, claves ni acceso administrativo**. Examina Nginx, Docker y las rutas públicas usando `--resolve HOST:443:127.0.0.1` con SNI correcto, sin pasar por un proxy HTTP. Debe indicar:

- Backend `127.0.0.1:3000/api/v1/health`: **200**.
- Web HTTPS `spdecode.xyz/`: **200**.
- API HTTPS `api.spdecode.xyz/api/v1/health`: **200**.
- API HTTPS `api.spdecode.xyz/api/v1/ready`: **503** intencional si `CLOUD_API_ENABLED=false`, no es un 502.
- Panel HTTPS `panel.spdecode.xyz/admin/login`: **200** desde cualquier red; el backend solo permite iniciar sesión con usuario y contraseña. El endpoint administrativo de sesión responde **503** hasta habilitarlo y **401** sin una sesión válida cuando esté habilitado.

Si la ruta local del panel da **502** y el acceso directo a Next.js `127.0.0.1:3000/admin/login` también falla, inspecciona `sudo docker logs --tail 80 spdecode-web-1`. Si el backend directo da **200** y el proxy da **502**, inspecciona `sudo tail -n 35 /var/log/nginx/error.log`; comprueba el `server_name` y el upstream del panel.

**No actives** `CLOUD_API_ENABLED` para intentar reparar un 502: es un interruptor de acceso al descifrador, no de red. Un 200 de `/health` solo confirma liveness, no Play Integrity, disponibilidad ni compatibilidad real.


## Error Docker: `decoder-worker` unhealthy tras emitir HTTPS

Si el certificado ya se emitió correctamente y `docker compose up` informó `dependency failed to start: container spdecode-decoder-worker-1 is unhealthy`, **NO repitas `resume-install.sh` ni Certbot**. Comprueba primero, sin mostrar variables privadas, qué ocurrió:

```bash
sudo docker ps -a --filter name=spdecode-
sudo docker logs --tail 80 spdecode-decoder-worker-1
sudo docker inspect --format '{{json .State.Health}}' spdecode-decoder-worker-1
```

El worker funciona como UID `65532` sin privilegios, mientras que el instalador clona como root con `umask 077`. Docker `COPY` preserva los permisos de archivos locales; en VPS los scripts pueden quedar modo `0600` y directorios `0700`, bloqueando su lectura. El Dockerfile ahora ejecuta `chmod -R a+rX /opt/spdecode` **dentro de la imagen**, donde solo existen fuentes de los motores; no cambia los secretos privados `/etc/spdecode`. Además prueba importar `server.py` y cargar las 240 rutas usando el mismo usuario restringido durante el build. El healthcheck permite el arranque más lento de VPS.

Continúa desde la etapa de Docker con:

```bash
cd ~/SP-DECODE
git pull --ff-only origin feat/cloud-c8-vps-installer-updater
sudo bash cloud/infra/vps/resume-services.sh
```

El recuperador comprueba TLS ya emitido, sincroniza solo `/opt/spdecode/repo`, reconstruye Docker y muestra el estado. **No regenera certificados ni claves**. Si el worker sigue fallando, la salida de `docker logs` y `docker inspect` determinará si son permisos, memoria/OOM, Python o Docker.


## Recuperación si Let's Encrypt recibió HTTP 404

**Error:** `unauthorized: Invalid response ... 404` para `spdecode.xyz`, `api.spdecode.xyz` y `panel.spdecode.xyz`. Significa que el servidor HTTP respondió pero **no entregó los archivos de desafío** creados en `/var/www/spdecode-acme/.well-known/acme-challenge/`. La causa más frecuente con el sitio provisional anterior es un virtual host Nginx duplicado.

**Diagnóstico importante:** el recuperador inicial comparaba únicamente el texto de respuesta HTTP y no mostraba si provenía de Nginx o de un proxy configurado mediante `HTTP_PROXY`/`ALL_PROXY`. Ahora fuerza conexión directa a `127.0.0.1:80` con `curl --noproxy '*'` y, si falla, imprime el código HTTP, un resumen de la respuesta, bloques de Nginx pertinentes y permisos del webroot. No assume que sea siempre un conflicto de hosts.

**No vuelvas a ejecutar `install.sh` completo**: el primer intento ya creó `/opt/spdecode/repo`, `/etc/spdecode/cloud.env` y otros directorios. No cambies los secretos ni los registros MX/TXT del correo.

Primero inspecciona:

```bash
sudo ls -la /etc/nginx/sites-enabled/
sudo nginx -T 2>&1 | grep -E 'conflicting server name|server_name|spdecode-acme'
```

Si `/etc/nginx/sites-enabled/spdecode` es el **enlace simbólico del sitio provisional SP-DECODE** hacia `/etc/nginx/sites-available/spdecode`, el rescatador puede desactivarlo y guardar una copia en `/etc/spdecode/backups` (no elimina el destino original). No toca sitios de terceros.

```bash
cd ~/SP-DECODE
git pull --ff-only origin feat/cloud-c8-vps-installer-updater

# Primero una comprobación conservadora (se detiene si encuentra un legacy activo):
sudo bash cloud/infra/vps/resume-install.sh

# Si aún falla, envía el bloque "observed HTTP" y "Relevant Nginx configuration".

# SOLO si el error señala precisamente el antiguo enlace
# /etc/nginx/sites-enabled/spdecode:
sudo bash cloud/infra/vps/resume-install.sh --disable-legacy-spdecode
```

El rescatador comprueba que los archivos previos existen, verifica el webroot por HTTP para cada host en `127.0.0.1:80`, solicita nuevamente el **mismo certificado Let's Encrypt** y finaliza Nginx, Docker y la CLI sin regenerar credenciales. Si localmente funciona pero Let's Encrypt sigue devolviendo 404, inspecciona la resolución A/AAAA pública, posibles CDN/proxy y la dirección pública del VPS. Antes de intentar múltiples validaciones seguidas, comprueba HTTP desde fuera para no alcanzar límites de emisión.

Para verificar manualmente la ruta de desafío:

```bash
sudo mkdir -p /var/www/spdecode-acme/.well-known/acme-challenge
echo SPDECODE-ACME-READY | sudo tee /var/www/spdecode-acme/.well-known/acme-challenge/test-spdecode
for name in spdecode.xyz api.spdecode.xyz panel.spdecode.xyz; do
    curl -i --resolve "$name:80:127.0.0.1" \
      "http://$name/.well-known/acme-challenge/test-spdecode"
done
sudo rm -f /var/www/spdecode-acme/.well-known/acme-challenge/test-spdecode
```

Los tres deben responder con HTTP 200 y `SPDECODE-ACME-READY`. El comando de prueba solo consulta Nginx en la VPS; después comprueba también los dominios públicamente antes de repetir Certbot.

## Instalación concreta: dominio spdecode.xyz y VPS OVHcloud

Tu infraestructura se configura así:

| Host público | Servicio | Ruta de acceso |
| --- | --- | --- |
| `https://spdecode.xyz` | Sitio web, documentación y privacidad | Next.js interno 127.0.0.1:3000 |
| `https://www.spdecode.xyz` | Redirección 308 al principal | Solo si añades `--www` y su DNS |
| `https://api.spdecode.xyz` | API Android C3 (solo `/api/v1/`) | Mismo Next.js interno, host separado |
| `https://panel.spdecode.xyz` | Panel C6: usuario y contraseña | Mismo Next.js interno, host separado |
| `soporte@spdecode.xyz` | Correo de contacto y notificaciones TLS | Se conserva el proveedor de correo actual |

**Importante:** el backend no utiliza puertos 8000 o 3001; son ejemplos antiguos de una arquitectura distinta. C3/C6 usan el **único** Next.js en `127.0.0.1:3000`. Redis y el worker siguen dentro de Docker y **no** deben tener puertos públicos. Los bloques de Nginx impiden abrir endpoints administrativos en el host API, o endpoints de descifrado en el host público.

Comprueba primero que los registros A de los tres hosts apunten a la **IP pública real de tu VPS** y que el certificado pueda emitirse en 80/443. No cambies los registros **MX, SPF, DKIM ni DMARC** de `soporte@spdecode.xyz`. El DNS lo gestiona el proveedor autoritativo del dominio, que no tiene por qué coincidir con tu registrador.

Si tienes una página provisional de Nginx instalada según instrucciones anteriores, haz backup de su configuración y elimina o deshabilita los virtual hosts duplicados **antes** de ejecutar el instalador. No ejecutes simultáneamente dos configuraciones distintas para `spdecode.xyz`, `api.spdecode.xyz` o `panel.spdecode.xyz`.

```bash
git clone --branch feat/cloud-c8-vps-installer-updater \
  https://github.com/Gh0stDeveloper/SP-DECODE.git
cd SP-DECODE
sudo bash cloud/infra/vps/install.sh \
  --domain spdecode.xyz \
  --api-domain api.spdecode.xyz \
  --panel-domain panel.spdecode.xyz \
  --email soporte@spdecode.xyz \
  --support-email soporte@spdecode.xyz
```

Agrega `--www` **solo** si `www.spdecode.xyz` ya resuelve hacia el VPS. Opcionalmente puedes suministrar `--expected-ip IP_PUBLICA_VPS` para abortar si alguno de los hosts resuelve a otra IP (útil frente a parking DNS o registros antiguos). Este parámetro comprueba DNS del servidor, nunca limita el inicio de sesión del panel.

Después de instalar, el generador de Android toma automáticamente `/etc/spdecode/api-domain` y compila `https://api.spdecode.xyz` dentro de **`libspdecode.so`**. El script **no** empaqueta `spdecode.xyz` como destino de API por error. El correo de soporte se muestra en el pie de página y en privacidad, pero esto **no envía ni configura correo SMTP**, MX o buzones.

**El sistema comienza cerrado:** `CLOUD_API_ENABLED=false`, `CLOUD_ADMIN_ENABLED=false`, `CLOUD_FORCE_MAINTENANCE=true`. Se necesitan configuración y evidencias de C7/Play antes de cambiarlo.


## 1. Instalar SP-DECODE Cloud en Oracle / AWS / DuckDNS

Necesitas Ubuntu/Debian 64 bits, un hostname (por ejemplo, DuckDNS) cuyo DNS A apunte al VPS y puertos **80/443 TCP** abiertos tanto en UFW como en Oracle NSG/security lists o AWS Security Group. Docker y Nginx quedan instalados automáticamente. Si el repositorio es privado, prepara acceso de lectura mediante clave SSH de despliegue; nunca pongas un token PAT en el comando.

```bash
sudo apt-get update && sudo apt-get install -y git
git clone --branch feat/cloud-c8-vps-installer-updater \
  https://github.com/Gh0stDeveloper/SP-DECODE.git
cd SP-DECODE
sudo bash cloud/infra/vps/install.sh \
  --domain spdecode.xyz \
  --api-domain api.spdecode.xyz \
  --panel-domain panel.spdecode.xyz \
  --email soporte@spdecode.xyz
```

El script solicita automáticamente un certificado HTTPS Let's Encrypt para sitio, API y panel con webroot de Nginx, instala renovación/reload, clona la rama controlada a `/opt/spdecode/repo`, genera secretos del servidor en `/etc/spdecode/cloud.env` con permisos root 0600 y despliega Docker Compose: Next.js, worker privado Python/Node/PHP y Redis en red interna. **API y administrador permanecen desactivados por defecto**, y `CLOUD_FORCE_MAINTENANCE=true`.

La página de login del panel será pública mediante HTTPS, pero las operaciones requieren un usuario y contraseña que se configuran después. No existe allowlist ni vinculación de sesión a IP. El instalador no registra DuckDNS ni abre automáticamente el firewall cloud.

En VPS pequeños ten presente que **la instalación de contenedores y la compilación Android son operaciones distintas**. Se recomiendan 2–4 GiB de RAM para el primer build de Docker, más espacio de disco de al menos 20 GiB si piensas compilar localmente. Una instancia económica no garantiza atender 200–300 operaciones de descifrado simultáneas: C7/C8 requieren benchmark y límites por sesión. En Oracle ARM64 se puede alojar el servidor pero el SDK/NDK de compilación Android suministrado aquí requiere x86_64; compila Android con GitHub Actions en ese caso.

## 2. Actualizador integral

```bash
sudo spdecode status
sudo spdecode logs web
sudo spdecode logs api
sudo spdecode logs panel
sudo spdecode logs worker

sudo spdecode update api
sudo spdecode update web
sudo spdecode update panel
sudo spdecode update worker
sudo spdecode update all
sudo spdecode update all feat/cloud-c8-vps-installer-updater

sudo spdecode backup
sudo spdecode rollback
sudo spdecode restart all
```

API, web y panel **comparten una misma aplicación Next.js**, así que los tres comandos despliegan conjuntamente la imagen web. En cambio el worker de descifrado sí es un contenedor separado y puede actualizarse sin reconstruir el frontend. El actualizador bloquea operaciones concurrentes con flock, exige repositorio limpio, hace git fetch del ref seleccionado y guarda el SHA previo, reconstruye el componente y comprueba el endpoint de salud. Si falla, intenta restaurar el código anterior y reconstruir contenedores. No realiza migraciones ni garantiza cero downtime; una actualización irreversible del estado persistente requiere restauración manual del backup.

Los archivos principales están en `/etc/spdecode/cloud.env` y `/etc/spdecode/install.conf` (root 0600), nunca se publican ni se añaden al Git. El comando `spdecode backup` crea copias sensibles root-only en `/opt/spdecode/backups`; conserva una copia cifrada externa.

## 3. Panel y credenciales privadas

```bash
# Configuración desde una terminal SSH interactiva:
sudo spdecode panel enable
# Solicita usuario, contraseña fuerte y confirmación sin mostrar la contraseña.
# Publica /admin/login para todas las conexiones HTTPS;
# /api/admin requiere una sesión autenticada.

sudo chmod 600 /root/service-account.json
sudo spdecode config google-service-account /root/service-account.json
sudo spdecode config set CLOUD_GOOGLE_PLAY_PACKAGE com.ghostdeveloper.spdecode

## El comando anterior ya habilita el panel y reinicia Next.js.
## Para desactivarlo después: sudo spdecode panel disable

# Mantenimiento de emergencia impuesto en servidor:
sudo spdecode config set CLOUD_FORCE_MAINTENANCE true
sudo spdecode restart web
```

El password administrativo se lee sin eco y se almacena como hash scrypt. El JSON de Google se conserva en variables privadas del servidor, no en Kotlin/C++ ni en JavaScript del navegador. Todos los proveedores de importación permanecen deshabilitados por defecto hasta suministrar credenciales autorizadas. Play Integrity exige validación de versión, paquete, licencia, dispositivos y Google Play Console: un servidor instalado no certifica esas verificaciones.

## 4. Compilar APK y AAB firmados para pruebas de Play Console

**AAB** significa Android App Bundle: es el archivo de carga recomendado para Google Play Console; el APK permite pruebas e instalación directa. Un AAB no se instala directamente como APK y debe firmarse con tu clave de subida registrada. La clave de firma de la aplicación de Google Play puede ser diferente de la clave de subida.

En VPS **x86_64** con al menos 12 GiB libres adicionales:

```bash
sudo spdecode android setup
```

Instala OpenJDK 17, Android SDK Command-Line Tools con SHA-256 verificado, API 35, NDK 27.2.12479018, CMake 3.22.1, Build Tools 35 y Gradle 8.11.1 verificado. Descarga de dependencias y compilación pueden consumir muchos recursos.

Si la aplicación ya tiene una clave de subida registrada, utiliza **la misma clave existente** (no crees otra):

```bash
sudo chmod 600 /root/upload-key.p12
sudo spdecode android signing configure /root/upload-key.p12 mi_alias
```

Solo para una aplicación nueva **sin clave registrada**, o con la autorización de Google para cambiar tu upload key:

```bash
sudo spdecode android signing generate spdecode_upload
```

Esto solicita una contraseña que no se muestra. Guarda la clave en `/etc/spdecode/keys/upload-key.p12` y las contraseñas en `/etc/spdecode/signing.env`; respáldalas cifradas fuera del servidor. Nunca generes otra clave en cada actualización.

Para compilar una nueva versión de prueba usando un `versionCode` mayor al del código fuente (y que también debe superar el máximo usado en Play Console):

```bash
sudo spdecode android build \
  --version-name 1.2.0 --version-code 26 --testing-only

# Actualizar código y compilar un nuevo paquete de prueba:
sudo spdecode update app feat/cloud-c8-vps-installer-updater \
  --version-name 1.2.0 --version-code 26 --testing-only

sudo spdecode android artifacts
```

El compilador crea un Git worktree temporal, modifica `versionName`/`versionCode` solo en esa copia, incorpora tu dominio HTTPS compilado en `libspdecode.so`, ejecuta `:app:assembleRelease :app:bundleRelease` y verifica la firma APK con apksigner, alineación 16 KiB, firma AAB con jarsigner, escaneo C5 del APK y hashes SHA-256 (se aceptan únicamente los perfiles ART/dexopt generados por Android Gradle Plugin, además del catálogo público; nunca materiales de descifrado). Guarda los paquetes y manifiesto en `/opt/spdecode/artifacts/vVERSION-CODE/`. No sobreescribe versiones firmadas existentes.

**NO se suben archivos automáticamente a Play Console**, **NO se publica una nueva versión pública** y **NO se fusiona con main**: el gate C7 continúa bloqueando producción hasta comprobar el servicio y Play Integrity reales. El AAB de este comando es un **artefacto de pruebas**, que puedes evaluar en un canal autorizado y cerrado una vez configurado Play Console. El script no asegura que un usuario pueda descifrar sin VPS ni Play Integrity real.

## 5. Archivos, seguridad y límites

- `/opt/spdecode/repo` — checkout de código gestionado.
- `/opt/spdecode/artifacts` — APK/AAB firmados y SHA-256; acceso root-only.
- `/opt/spdecode/previous.sha` — SHA para rollback.
- `/etc/spdecode/cloud.env` — secretos de API, Redis y administrador.
- `/etc/spdecode/signing.env` y `/etc/spdecode/keys/upload-key.p12` — claves de firma, root-only.
- `/etc/nginx/sites-available/spdecode.conf` — proxy HTTPS; el panel tiene autenticación por usuario/contraseña, sin bloqueo de IP.
- `/var/www/spdecode-acme` — desafíos Let's Encrypt.
- `cloud/infra/vps/tests/test_installer.py` — pruebas offline; GitHub Actions valida sintaxis, dominio y Compose.

Quienes tienen acceso root o al socket Docker pueden leer las variables del contenedor; restringe SSH/Docker y usa un gestor de secretos si el proyecto crece. Nginx solo expone la web local de Next.js, nunca Redis ni worker por un puerto directo. Para producción faltan: Play Integrity real, muestras autorizadas, privacidad, carga en VPS, monitorización, recuperación y revisión final C8. Las verificaciones CI no sustituyen una instalación en una VPS real.
