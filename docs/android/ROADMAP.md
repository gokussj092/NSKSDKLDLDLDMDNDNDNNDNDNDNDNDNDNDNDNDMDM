# Roadmap de ingeniería — SP-DECODE Android

> **Ampliación planificada — 1.1.26, build 41:** [plan de navegación y funciones](../PLAN_ANDROID_1_1_26_BUILD_41_2026_11_02.md). Incluye Formatos en Ajustes, análisis de APK con Próximamente, créditos, etiquetas del catálogo, errores/sugerencias y Acerca de. Estado: solo documentación. Las fases siguientes conservan el seguimiento histórico; esta ampliación no se declara implementada ni cerrada.

**Política:** existe APK Android alpha; no considerarla release de producción ni formatos certificados. No declarar fase cerrada sin código, CI y evidencia. Desarrollo en ramas de subfase y PR; actualizar docs/android/HANDOFF.md y status.json. Conservar todas las funciones actuales del bot.

## Actualización de seguimiento (2026-10-09)

- **Usuario:** A.2.4.3 ARM64/Android físico/16 KiB y A.2.4.4 archivos reales/variantes/versiones, pruebas en ejecución por su parte, aún sin evidencia consolidada en el repositorio.
- **Ingeniería:** PR #27 · B.5 y G.2–G.5. Filtros/orden/favoritos cifrados/retención/cola de 30 archivos/DataStore último UUID. Estado: CI #37903456589 Linux SUCCESS, Android API35 100/100 SUCCESS; nuevas correcciones de UX aguardando la última CI. Room y DI aún abiertos en B.5.
- **H:** seguridad final, firma y publicación estable pospuestas; no apto para declarar GO de producción.

## Cadena de dependencias

~~~mermaid
flowchart LR
  A["A Auditoría/Arquitectura"] --> B["B Base Android"]
  A --> C["C Motor offline"]
  C --> D["D Python"]
  C --> E["E JS/PHP"]
  B --> F["F UI premium"]
  B --> G["G Historial"]
  D --> H["H Release"]
  E --> H
  F --> H
  G --> H
~~~

## Fase A — Definición, auditoría y arquitectura

| Subfase | Alcance | Prueba de cierre |
|---|---|---|
| A.1 | PRD, requisitos offline/no login, flujos y exclusiones | PRD revisado |
| A.2 | Auditar 59 extensiones/48 scripts: dependencias, red, CLI, fixtures, errores, recursos, vigencia | revisión estática reproducible + plan de fixtures; validación dinámica y muestras pendientes |
| A.3 | Arquitectura por capas, modelos, puente Python, ruta de ports, SAF | diagrama, contratos, spike definida |
| A.4 | UI aprobada, tokens, wireframes editables, estados y golden visual | DESIGN_SYSTEM + SVG |
| A.5 | Seguridad: red nula, secretos, backups, amenazas y pruebas | SECURITY_AND_QA |
| A.6 | Continuidad: branch, docs, README y registros de fase | HANDOFF + status.json |

**Resultado actual:** A.1/A.3/A.4/A.5/A.6 documentadas; A.2.1 y A.2.2 verificadas por CI. **A.2.3 completó su corpus de referencia sintético Linux: 60 casos golden raw exactos para 59/59 sufijos, cero sin positivo (no implica versión externa ni Android)**. **A.2.4 en desarrollo: prototipo de paridad Android con puerta de CI en emulador; no implica 59 formatos soportados**. A sigue abierta.

### Subfases internas A.2 para seguimiento preciso

| Subfase | Estado inicial | Evidencia requerida |
|---|---|---|
| A.2.1 Inventario de 59 registros, 48 scripts y análisis sintáctico estático | verificado (CI success) | `audit_decoders.py`, 48 filas, 0 rutas faltantes, tests |
| A.2.2 Dependencias/recursos, I/O, riesgos para port Android | verificado estáticamente; riesgos documentados | DECODER_AUDIT.md, reportes CI y remediation list |
| A.2.3 Corpus y golden fixtures seguros (positivos/negativos) | **baseline Linux sintética completada: 60 casos exactos para 59/59 sufijos, 0 sin positivo; compatibilidad externa/Android NO verificada** | [A23_GOLDEN_CORPUS.md](A23_GOLDEN_CORPUS.md), manifest/hashes, generación local y CI |
| A.2.4 Paridad de salida bot vs adapter; versión de formatos | **en progreso:** primer host Android, porte Kotlin `.v2` solo para 2 muestras sintéticas, carga NPV endurecida; no existe compatibilidad Android general | [A24_PARITY_SECURITY.md](A24_PARITY_SECURITY.md), job emulador y CI del PR #15, ABI arm64 y pruebas C/D/E posteriores |

La fuente permanente de hallazgos está en [DECODER_AUDIT.md](DECODER_AUDIT.md), la política de muestras en [A2_FIXTURE_POLICY.md](A2_FIXTURE_POLICY.md) y el corpus en [A23_GOLDEN_CORPUS.md](A23_GOLDEN_CORPUS.md).

## Fase B — Proyecto Android nativo

| Subfase | Trabajo | Criterio de aceptación |
|---|---|---|
| B.1 | Android Gradle Kotlin DSL, Compose, JDK, paquete, manifest sin INTERNET | assembleDebug + lint |
| B.2 | Tema AMOLED/claro, tokens, scaffold, bottom tabs Inicio/Historial/Formatos/Ajustes | layout conforme a SVG |
| B.3 | Splash, Inicio, Histor./Favoritos, Formatos, Ajustes, Acerca de | navegación sin crash |
| B.4 | SAF y VIEW/SEND/SEND_MULTIPLE, URIs de terceros y MIME | pruebas desde explorador real |
| B.5 | Room, DataStore, ViewModel, DI, navegación y estado proceso | tests unit/UI |
| B.6 | Instrumentación, accesibilidad, pantalla compacta | APK debug instalada en emulador/dispositivo |

## Fase C — Motor Android offline

| Subfase | Trabajo | Cierre |
|---|---|---|
| C.1 | Registry generado y validado contra decoders.json | 59 sufijos, longest suffix, Unicode |
| C.2 | DecoderDescriptor, Request, Result, errors y tests | API estable, éxitos válidos |
| C.3 | lectura SAF limitada, cancelación, timeout y limpieza | inputs hostiles no rompen la UI |
| C.4 | spike Chaquopy y wheel ABI/16 KB para Crypto/argon2/msgpack | smoke real arm64 y emulador |
| C.5 | ExecutionRouter, puente Python, normalizador, estados | 2 fixtures decodificados en modo avión |
| C.6 | aislamiento/manifest/scan de red | cero permisos INTERNET y cero conexiones |

## Fase D — Python (39 scripts distintos, 48 sufijos)

| Subfase | Conjunto | Cierre |
|---|---|---|
| D.1 | TLS, e-V2Ray, HTTP Custom, HTTP Injector / Lite | goldens Linux/Android, negativos |
| D.2 | HTTP Tweak (.ht/.htb), NPV4 (.npv4/.npvt), Dark Tunnel, SSC | paridad y límites de memoria |
| D.3 | SSH, PB, ZIV, SUT, SOCKSIP, NetMod, VPN Lite y afines | fixtures + ARM64 |
| D.4 | restantes de matriz, multides, sufijos compuestos | 48/48 rutas Python reportadas |
| D.5 | revisión de versiones actuales y regresión | sin errores silenciosos |

**Nota:** los scripts recientes con run(bytes) son candidatos de integración temprana; los CLI heredados requieren puentes, no ejecución subprocess idéntica a Linux.

## Fase E — Ports Node.js/PHP (9 scripts, 11 sufijos)

| Subfase | Trabajo | Cierre |
|---|---|---|
| E.1 | hat.js y recurso nodehat.json | vector .hat paritario |
| E.2 | rez.js (.rez/.rezl/.tvt), sks.js | bytes / JSON golden |
| E.3 | stk.js, modulepro.js, chicosp.js | .stk/.epro/.npv2 verificados |
| E.4 | sksplus.php, jez.php, hrt.php | prueba de AES/IV y corruptos |
| E.5 | consolidar registry y status por sufijo | no depende de Node/PHP externos |

## Fase F — Interfaz premium

| Subfase | Trabajo | Cierre |
|---|---|---|
| F.1 | Resultado campos/tarjetas, raw text, warnings | golden visual SVG |
| F.2 | Copiar, compartir y revelar secretos con censura | tests privacidad y TalkBack |
| F.3 | Exportar TXT y JSON solo cuando sea válido | SAF/create-document tests |
| F.4 | progreso, cancelación, errores y vacíos | estados correctos |
| F.5 | i18n es/en/pt-BR/ar: selector offline + Android per-app language, RTL real, cadenas UI y accesibilidad | cuatro idiomas completos, golden LTR/RTL, 320dp y 200 % font; resultado del decoder sin traducción |

## Fase G — Historial y gestión

| Subfase | Trabajo | Cierre |
|---|---|---|
| G.1 | Room con cifrado Keystore para payloads | DB migration/corrupt tests |
| G.2 | buscar metadatos, filtros y favoritos | secretos nunca FTS plaintext |
| G.3 | eliminar, retención, exclusión backups | test borrado |
| G.4 | lote de archivos con cola/cancel | 30 archivos mixtos |
| G.5 | ajustes, background y process death | restauración y estados |

## Fase H — Seguridad final y publicación

| Subfase | Trabajo | Cierre |
|---|---|---|
| H.1 | CI Android + pipeline legacy del bot | todos jobs relevantes success |
| H.2 | compatibilidad formato-by-formato y suite golden; paridad `rawText` entre es/en/pt-BR/ar | matriz con evidencia, datos exportados idénticos entre idiomas y sin traducciones |
| H.3 | revisión seguridad, dependencias, permisos, fuzz | 0 blockers P0 |
| H.4 | rendimiento, ABI, 16 KB, Android 7–16 | pruebas medidas por dispositivo |
| H.5 | icono, splash, changelog y créditos | recursos finales |
| H.6 | firma APK, AAB opcional, GitHub Releases | descarga e instalación real |
| H.7 | mantenimiento y política de versiones de formatos | runbook de regresiones |

## Versiones y puertas de salida

0.1-alpha: shell e importación; 0.2-alpha: motor y dos formatos; 0.3-beta: formatos+UI+historial; 0.9-rc: cobertura y hardening; 1.0 estable: seguridad, compatibilidad documentada, CI verde y APK firmada. No llamar 1.0 «59 soportados» sin 59 casos verificados.

**NO-GO** si: conexión de red, login, dependencia de Telegram/Termux, secretos sin protección, formatos anunciados sin fixtures, crashes de imports, pantalla visualmente alejada de DESIGN_SYSTEM o faltan checks obligatorios.

## Registro para cada PR

Objetivo; rama; SHA; rutas cambiadas; formatos/fixtures; CI job+URL+estado; resultados dispositivo/ABI; capturas golden; riesgos; próxima subfase. Actualizar HANDOFF.md + status.json en el mismo PR.


### Seguimiento 0.3.5-alpha (preparación técnica, no cierre de H)

Se elimina la duplicación de vistas crudas/detalladas del resultado. B.5 añade Room exclusivamente para índices UUID/fecha sin credenciales, una capa de servicios local y restauración de pestaña, con pruebas de migración desde registros cifrados anteriores; Navigation Compose completo sigue pendiente si se decide necesario. H incorpora preparación de firmado y validación con puertas NO-GO; firma con credenciales reales, auditoría final y publicación quedan bloqueadas hasta pruebas A.2.4.3, A.2.4.4 y seguridad/QA.


### Nuevo incremento 0.3.7-alpha — textos cifrados

Solicitado tras integrar los Secrets de keystore. Se añade una entrada independiente
de texto para el catálogo específico del bot, portando los protocolos textuales
con algoritmos locales. Los formatos multipart SSC y Dark retienen partes
temporalmente sin persistencia. Ver `docs/android/TEXT_PROTOCOLS.md`.
Estado: implementación pendiente de validación CI y pruebas con textos reales.
Mantener H stable en NO-GO hasta firmado real V1/V2/V3 y upgrades verificados.


### Preparación de producción Android 1.0.0

El propietario autorizó nombrar 1.0.0 estable y firmar exclusivamente mediante su
keystore de GitHub Secrets. Tras pasar Validate SP-DECODE en `main`, un segundo
workflow ejecuta `assembleRelease`, inspecciona V1/V2/V3, verifica alineación
a 16 KiB, genera SHA-256 y publica el **artefacto privado de producción**.
No se dispara desde PR. La publicación pública GitHub Release conserva un gate
GO basado en evidencia, donde aún debe documentarse instalación/actualización
con la nueva firma definitiva y pruebas reales de los textos recientes.

