# UT Loop Pro VPN: reinvestigación, descarga todavía pendiente

Fecha **2026-11-01**. El propietario seleccionó UT Loop expresamente tras MM.
Esta entrega trata únicamente UT Loop; no completa CREEB ni AM por haber cambiado
la selección. No se avanza automáticamente a otra app.

**Resultado:** se corrige una diferencia real del descargador, se añade un
diagnóstico seguro y se revalida el lector offline. **No se obtuvo una descarga
OTA firmada de producción; la ficha permanece desactivada.** El criterio de
cierre sigue exigiendo descarga real y comparación íntegra, no un mock ni el
catálogo incluido.

Goku: `gokussj092/NSKSDKLDLDLDMDNDNDNNDNDNDNDNDNDNDNDNDMDM`, rama
`fix/http-jireh-current-method`, base de esta entrega
`22bbdd27d428083370ac61c0b07b6ea006535e4c` (MM completado).
main se verificó en `5a1c93a483619370ab0a155ed3d0ecd19ee8169c`; esta rama no
estaba fusionada. No hay AGENTS.md en el árbol del repositorio.

## Original vigente y recuperación

Google Play consultado en vivo y el XAPK descargado muestran **22.10.26/build65**,
paquete **loop.uchetechs.vpn.pro**. minSDK24,targetSDK36, variante arm64-v8a.
El APK base y DEX son idénticos a los documentados el2026-10-22; se confirmó
la vigencia en lugar de asumir que había una actualización de método.

| Pieza | Bytes | SHA256 |
| --- | ---: | --- |
| XAPK actual ARM64 | 51181399 | `96657e6cf02cb4699a7d8e0c8dd099f7e145ec6a64a163f36b9707c40fdbb27c` |
| Base APK | 23168959 | `8df86b9839e7fd77463081cea983136c8c6684a2506777d622b7e4cea965abb8` |
| classes.dex | 10356852 | `0009e8d46a5d96b19c7a7fa372449e98b69303a9e46a68477f8b9737afdce833` |
| Catálogo incluido Base64 | 1544 | `23c3f897d17646bd610db2d253da8dcbe413ea29b7997123457ed175ed8bcb15` |
| HTML remoto observado | 195 | `5b131ca14aa96311d3432b0062c7443d3b0e6346ec279bd376a75f0a76bcd5d7` |
| PNG original | 74425 | `8f01bceeb6a4f352e0b5b17ffe43df37ff4c5c78aaaf250696e540ae3f779b17` |

Signer SHA1 `baec27ecdf8c9ebddca1e736cc1cc97ffeab8c9e`;
SHA256 `fc692b18c1e532fda8b4cf485aa26355c006b3dc4442bf228684209cdb58a1d6`.
No se afirma una descarga directa desde Google Play ni una verificación del
signer por Google. Fuente de bytes:
`https://d.apkpure.net/b/XAPK/loop.uchetechs.vpn.pro?version=latest`.

Original actual guardado correctamente:
**UT-Loop-Pro-VPN-22.10.26-build65-arm64.xapk**,
**`libfile_153a214f623881919ebc39482a31447d`**.
Existe también el APKS previo identificado por su nombre
`UT Loop Pro VPN_22.10.26.apks`, `libfile_d40424d4cd70819181da316abb5243cf`;
no se volvió a materializar ni se afirma haber leído su contenido en esta entrega.
APK/SO/DEX, catálogos reales, datos descifrados e inventarios quedan fuera de Git.

## Flujo activo confirmado

JADX1.5.6 terminó exit3 con21 errores generales; no es una descompilación total.
StringFog Base64/XOR, clave confirmada del wrapper L5.b:2438 llamadas en71
fuentes. El helper existente stringfog_strings.py reproduce la resolución.

MainActivity crea core.h con util.h.f19120a para comprobar actualizaciones;
el callback aplica **util.r.c** para RSA y **util.r.b** para GCM. No se usa una
URL de actualización de APK como si fuera un catálogo VPN.

Fuente fija:
`https://api.utloop.xyz/v1/ota/config?package=loop.uchetechs.vpn.pro`.

En **core.h.a**, GET con X-Api-Key:

1. La clave fija coincide con la constante ya versionada en el script.
2. Obtiene el acceso cacheado/renovado mediante OtaAccess.d.
3. **Si devuelve null, igual realiza el GET sin X-Ota-Access ni X-Ota-Iid.**
4. Si obtiene acceso, añade ese access y el iid propio persistente.
5. Si recibe401, invalida la caché; no crea una respuesta falsa ni usa el asset
   como si fuera una descarga remota.

El script anterior rechazaba ambos ausentes antes de realizar la petición.
Se permite esa rama original y se rechaza un par incompleto o mal formado.
No hay intento de inventar tokens, generar otra identidad por descarga,
reducir la validación RSA ni sortear un entitlement premium.

No se encontró un User-Agent específico en este flujo ni un override global
http.agent. El nombre UT Loop Pro VPN/22.10.26 del script no venía del APK y se
retira. El CLI usa **Dalvik/2.1.0 como prefijo genérico**; no lo presenta como el
http.agent completo de un teléfono real. UT_LOOP_USER_AGENT permite suministrar
el valor real de una instalación propia. Se mantiene validación TLS y no se
aceptan redirecciones ni URLs externas suministradas por el usuario.

## Acceso oficial y renovación

OtaAccess.a realiza el flujo oficial:

- POST a `/v1/nonce` con JSON vacío y X-Api-Key.
- Google Play Integrity: IntegrityManagerFactory, nonce del servidor y cloud
  project743275131312. El token es emitido por Google para la instalación.
- POST a `/v1/ota/access` con **packageName, integrityToken, nonce, iid**.
- Guarda **access, issued_at, expires_at** en preferencias propias. El iid
  proviene de UUID una sola vez y se conserva; no es una identidad de otro usuario.

La respuesta tiene ttl; el default del consumidor es600 segundos. La app
recorta el máximo a24h, resta5 minutos para renovación y respeta un mínimo de
1 minuto en caché. Un403 establece espera de1h y limpia el acceso; un401 de
la descarga limpia la caché para que se renueve por la vía oficial.

**El access no es una credencial fija extraíble del APK.** API key, clave de
formato y token OTA tienen funciones distintas. Si la fuente exige sesión,
se requiere acceso oficial vigente y una vía autorizada de renovación; poner
placeholders en variables no lo resuelve. No se encontró un acceso, instalación
registrada o respuesta OTA real aportados anteriormente para este caso.

No se hizo un nuevo sondeo de nonce/access sin disponer de Integrity legítimo.
La revisión automática que citaba la documentación de2026-10-22 es un antecedente
histórico, no una denegación nueva de esta entrega. Se hizo la lectura fija del
catálogo que la app permite intentar sin sesión cacheada.

Premium mantiene POST fijo a `/v1/premium/config` con packageName/entitlement
oficial. No se llamó al servicio premium sin una suscripción autorizada ni se
validó un catálogo premium real.

## Descarga real y diagnóstico

Se ejecutaron la rama original sin sesión cacheada y una repetición mediante
**CLI --probe corregida**. Ambas: **HTTP200, Content-Type text/html,195 bytes**,
HTML Site Unavailable y el hash indicado arriba. No contiene data/sig.
La CLI sale1 con **REMOTE_HTML_RESPONSE**, sin imprimir clave, tokens o cuerpo.

Esta observación **no demuestra falta de token ni caída global del proveedor**.
El usuario ha indicado que la app puede funcionar desde su teléfono. Queda
contrastar la fuente desde una red/VPS que la alcance y usar acceso oficial
solo si el servidor lo exige. No se atribuye el HTML a una causa no comprobada.
No se intentó sustituir el host, adivinar otras rutas o usar un feed premium.

```bash
# En un checkout con dependencias instaladas; no activa ni despliega un proveedor.
python decoders/Python/apps/UT_Loop_Pro_VPN/server_catalog_decoder.py --probe
```

El diagnóstico solo emite metadatos, HTTP, tamaño y hash. En éxito verifica RSA
con la clave pública original y GCM, y publica versión/recuentos sin credenciales
ni valores de configuraciones. Si existe un par legítimo propio puede usarse
UT_LOOP_OTA_ACCESS/UT_LOOP_OTA_IID; no se debe pegar en Git, fixtures o logs.

Errores diferenciados: HTML,401/403,transporte,redirección,tamaño,codificación,
y firma/catálogo inválidos. Una respuesta sin firma se acepta únicamente como
entrada offline explícita, jamás como una descarga verificada.

## Verificación y estado que puede afirmarse

- **7 Python aprobadas,0 omisiones:**6 UT Loop y1 registro C8. GET con/sin sesión,
  pares inválidos, User-Agent, POST premium fijo, errores, diagnóstico sin datos
  privados, firma obligatoria, GCM, banners, CLI y worker.
- **50 Node aprobadas,0 omisiones:** catálogo, sincronización de versiones y
  controles persistentes; ficha UT Loop desactivada y PNG original intactos.
- Catálogo **incluido** real:1.0,1 servidor/1 tweak; todo el JSON igual a
  Java/JCA independiente, CLI desde /tmp y worker aislado no parcial. La clave
  RSA del lector coincide con el APK. No es una respuesta remota firmada.
- Se conserva la cobertura sintética RSA/GCM/banners con firmante exclusivamente
  de pruebas, que producción rechaza. No se fabrica un firmante de UT Loop.
- Generador de formatos aprobado: fuente59/57 fichas,C0240/C8255/29 overrides.
  Siguen **9 fichas remote:null**; UT Loop no se mueve a resueltos.

No se añadió el broker público, una ficha habilitada, controles de activación
nuevos, extensiones, perfiles exportados ni un escritor. No se fusionó, desplegó,
compiló APK/AAB ni disparó CI manual. Los métodos ya completos, incluido MM,
se conservan. [Pruebas y comandos](../../decoders/Python/apps/UT_Loop_Pro_VPN/TESTING.md).

## Próximo paso concreto

Validar --probe desde el VPS o la red donde funciona la app original. Si devuelve
el sobre firmado, recuperar sus bytes privadamente para comparar todo el JSON
con JCA/worker y completar el broker/C12/gateway. Si devuelve401/403, completar
el acceso oficial y su renovación antes de habilitarlo. Si sigue devolviendo
HTML, resolver primero la accesibilidad con evidencia de esa red. No volver a
certificar el catálogo incluido como sustituto ni anunciar descarga terminada.
