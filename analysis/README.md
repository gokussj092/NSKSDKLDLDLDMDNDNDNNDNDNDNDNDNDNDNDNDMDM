# analysis/ — Archivo obligatorio de investigación SP-DECODE

**NUEVA REGLA PERMANENTE DE TRABAJO (2026-11-02):** Toda aplicación nueva, nuevo método o actualización de un método ya existente debe guardar sus **scripts utilizados, herramientas, comandos, pruebas, metadatos de la APK y evidencias** en un expediente propio dentro de esta carpeta ANTES de anunciar el método como integrado/verificado.

La política normativa completa es [METHOD_EVIDENCE_POLICY.md](METHOD_EVIDENCE_POLICY.md). Es obligatoria para investigadores, colaboradores y asistentes de IA del repositorio.

## Ubicación

- `analysis/<package_android>/<version_code>/MANIFEST.json`
- `analysis/<package_android>/<version_code>/ANALYSIS.md`
- `analysis/<package_android>/<version_code>/REPRODUCE.md`
- `analysis/<package_android>/<version_code>/RESULTS.md`
- `analysis/<package_android>/<version_code>/tools/` — **scripts de investigación propios empleados**, no solo el código final
- `analysis/<package_android>/<version_code>/tests/` — pruebas/fixtures sin secretos

Los expedientes enlazan al decodificador operativo en `decoders/Python/apps/` y a las utilidades compartidas en `scripts/apk_analysis/`; NO reemplazan ni eliminan esas rutas. Si se usó una herramienta compartida, registrar versión, ruta/hash y guardar un script/wrapper reproducible de la invocación por aplicación. Si se utilizó un script creado para la investigación, guardar el script físicamente en tools/.

Un resultado **no confirmado** también se archiva, con estado PENDING, PARTIAL o FAILED y las razones reales. No inventar éxito. No subir APK privado, datos de terceros, cuentas, claves ni archivos descifrados sensibles.

**La obligación documental ya está vigente.** El validador inicial de CI F7-A0 existe y fue probado (11/11 tests); su cobertura ampliada y la protección de rama como check requerido siguen pendientes. Sin expediente, los métodos nuevos NO se consideran finalizados.

## Avance F7-A0 (2026-11-06)

[Inventario y gate inicial](../docs/FASE_7_A0_INVENTARIO_Y_GATE_2026_11_06.md): scripts compartidos registrados, dependencias directas sin aprobación automática y comprobación documental en CI. **Etapa parcial**, sin análisis APK activo. [Seguimiento detallado A0–A9 y pendientes](../docs/FASE_7_SEGUIMIENTO_ESTADOS_Y_PENDIENTES_2026_11_06.md).

## Proyecto futuro que consumirá estas evidencias

[Análisis automático de APK — dos salidas](../docs/FASE_7_APK_AUTOANALISIS_DOS_SALIDAS_PENDING_2026_11_02.md): A) informe estructurado con metadatos y hallazgos; B) código propuesto por IA más pruebas de validación. Ambas funciones permanecen deshabilitadas y pendientes de desarrollo.

El archivo histórico [SOCKSIP_VER8_VER7_VER6_STUDY.md](SOCKSIP_VER8_VER7_VER6_STUDY.md) se conserva; no es un expediente por paquete/build de la nueva política.

## Expedientes por aplicación

- [com.halcon.connect /1391 — Halcon R Net](com.halcon.connect/README.md): VERIFIED_REAL: petición autorizada200, catálogo635/101 completo igual a JCA/CLI/worker; integrado en código. Prueba de Node real en VPS pendiente.

- [com.alsaher.vip / 2 — ALSAHER VIP](com.alsaher.vip/README.md): VERIFIED_REAL; catálogo remoto9.9.58/14 servidores/3 HTTP/9 SSL, JSON entero igual a Java/CLI/worker. Solo Cloud; Node/VPS pendiente.

- [dastan.prince.myvpnksa / 35 — FNF TUNNEL BD](dastan.prince.myvpnksa/README.md): VERIFIED_REAL; remoto82.0/28 servidores/1193 payloads, documento entero igual a Java/CLI/worker. Solo Cloud; Node/VPS real pendiente.

- [com.appxrayservice.namovpn / 35 — NAMO VPN](com.appxrayservice.namovpn/README.md): VERIFIED_REAL; remoto22.3/14 servidores/13 redes, JSON entero igual a Java/CLI/worker. Constante de formato incluida en código; Node/VPS real pendiente.

- [com.doriaxvpn.unlimited / 129 — HTTP Conexión](com.doriaxvpn.unlimited/README.md): VERIFIED_REAL; consulta automática de URL/contraseña Firebase, catálogo107/244 servidores/5325 campos GCM, entero igual a JCA/CLI/worker. Caché1h/reintento único. Solo Cloud, Node/VPS pendiente.

- [Speicers`Turbo VPN 217.4.4 / build217](netfree.mx.anuncios/217/ANALYSIS.md): remoto17/266 servidores +2/2 usuarios, JCA/CLI/worker completos; scripts y recuperación conservados.

- [Hex Custom.apk de MediaFire: recepción pendiente](_intake/mediafire-ypaiywpzrvslef1/README.md): HTML de 195 bytes, Site Unavailable, sin APK ni identidad confirmada.

- [Genis VPN / com.doriaxvip.tunnel / 76](com.doriaxvip.tunnel/76/ANALYSIS.md): VERIFIED_REAL; remoto 1114 / 84 servidores / 658 campos CBC, JSON entero igual a JCA/CLI/worker. Solo Cloud; Node/VPS pendiente.

- [XXPICore Tunnel / build118](pro.xxpicore.tunnel/README.md): catálogo remoto2.427,64 servidores/1240 redes/7837 campos; entero igual a JCA/CLI/worker. Solo Cloud; Node/VPS pendiente.


2026-11-09: [Thailand build3](thailand.vpn.globalvpn/3/ANALYSIS.md), [KHAM build24](com.khamvpn.net/24/ANALYSIS.md), [AR PRO build2 recheck](noob.arpro.vpn/2/ANALYSIS.md). Complete remote JSON verified for the first two; AR PRO source returns HTML, pending.
