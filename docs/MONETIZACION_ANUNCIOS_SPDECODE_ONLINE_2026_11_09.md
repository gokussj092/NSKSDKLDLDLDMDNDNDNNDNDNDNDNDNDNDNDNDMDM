# SP-DECODE Online — Arquitectura e integración de publicidad Unity LevelPlay

**Fecha:** 2026-11-09  
**Rama:** feat/nuevas-integraciones (rama Online; no alterar main ni feat/version-offline-apk)  
**Estado:** DOCUMENTACIÓN, SIN SDK IMPLEMENTADO NI ANUNCIOS ACTIVADOS.  
**Documento relacionado:** docs/MONETIZACION_LICENCIAS_OFFLINE_API_IP_2026_11_09.md

## 1. Productos y reglas innegociables

- **SP-DECODE Online:** aplicación gratuita que envía operaciones de descifrado al backend. Solo esta variante podrá incorporar publicidad previa aprobación de las redes.
- **SP-DECODE Offline:** aplicación de pago único con hasta tres dispositivos por licencia y descifrado local después de la primera activación. **No contiene SDK, red ni pantallas de publicidad.**
- Se construirán **dos APK independientes** con applicationId distintos. No convertir el producto en una única aplicación con interruptor Online/Offline.
- La monetización nunca debe cambiar la lógica de descifrado, exigir ver un anuncio para obtener un resultado ya calculado, mutilar JSON, añadir información sensible a SDKs de anuncios o impedir la exportación.
- Unity LevelPlay es la plataforma de mediación preferida; Unity Ads se configura como red para intersticiales. Todas las redes y el aplicativo deben estar aprobados para distribución por APK fuera de Play antes de anuncios reales.

## 2. Matriz de formatos verificada

| Ubicación | Formato | Fuente/limitación | Estado previsto |
|---|---|---|---|
| Resultado correcto de archivo | Intersticial (video o gráfico) | Unity Ads mediante LevelPlay, si aprobada | Primera fase |
| Resultado correcto de catálogo | Intersticial (video o gráfico) | Mismo Ad Unit; placement distinto | Primera fase |
| Lista del catálogo, entre elementos | Native | Requiere red mediada que soporte nativos, p. ej. ironSource Ads, previa aprobación | Segunda fase |
| Inicio, área no intrusiva | Banner | Opcional; solo si no deteriora UX | Más adelante |
| Botón de visualización voluntaria | Rewarded | No habilitar aún; exigir beneficio verdadero aprobado por red | Fuera de alcance inicial |
| SP-DECODE Offline | Ninguno | Ningún SDK de anuncios | Permanente |

**Aclaración importante:** la plataforma LevelPlay **sí tiene integración de anuncios nativos Android**. Sin embargo, la tabla oficial de redes mediadas muestra Native para ironSource Ads y no para Unity Ads; **no dar por hecho que Unity Ads sirve nativos**. El formato nativo no debe anunciarse disponible hasta identificar y aprobar una red que efectivamente lo abastezca.

Documentación:
- https://docs.unity.com/en-us/grow/levelplay/platform/fundamentals/mediated-networks
- https://docs.unity.com/en-us/grow/levelplay/sdk/android/native-ads-integration
- https://docs.unity.com/grow/levelplay/sdk/android/interstitial-integration
- https://docs.unity.com/grow/levelplay/sdk/android/banner-integration

## 3. Flujo después de descifrado exitoso (acuerdo de producto)

Objetivo: mostrar un intersticial inmediatamente **después de recibir el resultado correcto y ANTES de abrir el visor JSON**, evitando que el usuario cierre la app sin haber tenido oportunidad de ver publicidad. Pero la lectura del JSON es incondicional.

Secuencia:

1. Usuario inicia archivo o catálogo. Subida/proceso/descarga de resultados **sin publicidad**.
2. El servidor confirma SUCCESS y el cliente recibe el JSON **completo y verificable**. Antes de intentar anuncio, conserva el resultado de modo que sobreviva a la rotación de pantalla y, cuando proceda, recreación del proceso.
3. La app comprueba: está en primer plano, elegibilidad de la operación, consentimiento, SDK inicializado, intersticial precargado, placement no capado, frecuencia y límite diario.
4. **Si todas** las comprobaciones son afirmativas, presenta intersticial mediante el SDK. El botón X, duración y cierre pertenecen al anuncio real y no se simulan en SP-DECODE.
5. Al cerrar o fallar el anuncio, abrir el visor JSON **exactamente una vez**. No solicitar un anuncio nuevo para reemplazar uno fallido.
6. Si el anuncio no está listo, no hay fill, el usuario negó consentimiento cuando corresponde, la app está en segundo plano o se excedió el límite, abrir el JSON **inmediatamente**, sin esperar cargas publicitarias.

Reglas anti-regresión:
- Un archivo exitoso y un catálogo exitoso son eventos distintos, pero si una misma operación cruza ambos flujos, **no puede haber dos intersticiales**.
- Nunca mostrar intersticial en error, cancelación, reintentos, descifrado parcial, resultados reabiertos, importación inválida o por pulsar botones de copiar/exportar.
- No superponer publicidad sobre la vista de JSON ni bloquear las operaciones completadas.
- No introducir anuncios después de seleccionar opciones pequeñas o en cada toque.
- Si un proceso acaba estando la aplicación en segundo plano, **no mostrar anuncios por encima de otras aplicaciones**. Al volver, el resultado está disponible.
- La carga y visualización no debe forzar ANR ni reinicios; usar listener idempotente que controle las transiciones a resultado.

Máquina de estados por operationId:

  RUNNING -> SUCCESS_READY -> (AD_ELIGIBLE -> AD_SHOWING -> RESULT_VISIBLE) | RESULT_VISIBLE
  RUNNING -> FAILURE_VISIBLE

Datos mínimos: operationId no sensible, identificador seguro del resultado, adOpportunityConsumed, adShownAt y estado de ciclo de vida. El resultado no sale hacia la red publicitaria.

## 4. Publicidad dentro de la lista de catálogos

- Usar un componente Native real, identificado como **Publicidad** y registrado mediante las APIs de la red; no fabricar una celda que aparente ser un servidor VPN.
- Distribución experimental de UX: un espacio publicitario después de **5–8 elementos reales**, máximo uno visible simultáneamente; esos valores **no** son condiciones oficiales de Unity y no garantizan ingresos.
- No insertar anuncios donde se encuentren botones táctiles de descargar, cancelar, copiar o seleccionar servidor.
- No duplicar impresiones cuando el usuario hace scroll, rota la pantalla o una lista virtualizada recrea celdas. Gestionar ciclo de vida del NativeAd y destruir objetos cuando correspondan.
- Si no existe red aprobada para anuncios nativos o no hay fill, la lista sigue funcionando sin espacios engañosos. Un banner verdadero puede valorarse como formato alternativo **solo** si está permitido por la red y su diseño.
- No precargar listas gigantes de anuncios ni multiplicar llamadas cada vez que el usuario mueve el dedo.

## 5. Frecuencia (configuración inicial sugerida)

| Control | Inicial |
|---|---|
| Tiempo mínimo entre intersticiales | 10 minutos |
| Máximo de intersticiales por usuario/día | 3 |
| Por operación completada | 1 oportunidad, nunca dos |
| Anuncios de error, durante procesamiento, visor JSON | 0 |
| Offline | 0 |
| Native en catálogo | 1 por bloque de 5–8 resultados, sujeto a UX |

La app aplicará un límite global conjunto a placements de archivo y catálogo. Capping y pacing de LevelPlay deben configurarse adicionalmente para respetar las restricciones de la red. No confundir un intervalo de tiempo con una garantía frente a medidas contra tráfico inválido.

## 6. Implementación Android propuesta

- Integrar el SDK nativo Android LevelPlay **solo en la variante Online**, mediante Gradle y repositorio oficial Maven Central. No instalar Unity Engine.
- Al 2026-11-09, el changelog oficial documenta **LevelPlay Android 9.7.0 (2026-10-22)**; elegir versión compatible con Gradle/AGP/Kotlin, SDK y adaptadores al ejecutar la integración, y fijar todas las versiones para CI.
- Añadir adaptador Unity Ads para los intersticiales y adaptar el manifiesto únicamente en Online. Para Native añadir por separado el adaptador de una red nativa aprobada (no asumir Unity Ads Native).
- Gestionar Initializing -> Ready -> Loaded -> Showing -> Closed/DisplayFailed. Crear objetos Ad Unit después del callback de inicialización, precargar sin bloquear el descifrado y comprobar isAdReady junto con el límite del placement antes de mostrar.
- La lógica de presentación se mantiene en un módulo aislado del backend del descifrador, visor JSON y mecanismos HPKE actuales. La aplicación Offline excluye SDK y adaptadores en tiempo de compilación, **no solo por bandera runtime**.
- Cuidar R8/ProGuard y reglas oficiales de los adaptadores; validar con APK/AAB release y pruebas de ANR/crash.
- Reservar un callback de cierre/fallo idempotente para abrir el resultado una sola vez; protegerlo contra doble evento y recreación de Activity.

Referencias:
- https://docs.unity.com/en-us/grow/levelplay/sdk/android/sdk-integration
- https://docs.unity.com/grow/levelplay/sdk/android/changelog
- https://docs.unity.com/en-us/grow/levelplay/sdk/android/networks/guides/unity-ads
- https://docs.unity.com/en-us/grow/levelplay/sdk/android/integration-helper

## 7. Panel administrativo (posterior a pruebas de cliente)

Sección propuesta: **Publicidad Online**.

Controles a documentar/implementar:
- Activar/desactivar globalmente (kill switch).
- Intersticial de archivo, intersticial de catálogo, Native catálogo y banner opcional: controles separados.
- Intervalo mínimo y límite diario; parámetros mínimos y máximos validados en backend.
- Modo pruebas, sin anuncios de producción para testers.
- Métricas de oportunidades, impresiones entregadas, fill, errores, eCPM, ingresos y retención/ANR, usando datos legítimos de LevelPlay y medición propia mínima.

Seguridad: exigir autenticación/roles y origen/CSRF para cambiar controles; auditar, no filtrar llaves de API ni credenciales de Unity al navegador. Configuración pública para la app, pero nunca el secreto de firma del administrador. Un kill switch desactiva nuevas oportunidades, **no** descifrado ni lectura de JSON.

## 8. Privacidad, cumplimiento y aprobación antes del lanzamiento

- Presentar SP-DECODE como **utilidad de análisis y decodificación de configuraciones**; no opera conexiones VPN. Revisar con Unity su compatibilidad, declarando APK distribuida fuera de Google Play y pruebas/canal Play existentes. La aceptación la determina el proveedor, no la mera categoría descrita por el desarrollador.
- Revisar las políticas de contenido, ubicaciones, inventario recompensado y tráfico inválido de Unity antes de activar producción.
- Política de privacidad/consentimiento: identificar proveedores, datos recopilados, retención y país; usar un gestor de consentimiento/opt-out para jurisdicciones donde aplique, antes de inicializar SDK cuando corresponda. La aplicación principal sigue funcional sin anuncios.
- Configurar app-ads.txt en el dominio **solo con líneas facilitadas/validadas por las redes**; no inventar IDs.
- Jamás compartir contenidos de archivos, claves VPN, payloads, resultados JSON, credenciales, enlaces privados de catálogos, correos ni datos de cliente con SDK publicitario.
- No incentivar visualizaciones o clics repetidos, no solicitar a usuarios que vean anuncios únicamente para subir ganancias y no generar tráfico artificial desde emuladores, proxies o redes automatizadas.
- No instalar SDKs ocultos ni usar protección anti-tamper para obligar a ver anuncios cuando no están disponibles.
- Probar usando anuncios de prueba; no clickear anuncios reales para test.

Fuentes oficiales:
- https://unity.com/legal/content-policy
- https://unity.com/legal/invalid-activity-policy
- https://unity.com/pages/unity-operate-policy-center
- https://docs.unity.com/en-us/grow/levelplay/sdk/android/get-started

## 9. Matriz de QA

| Prueba | Resultado esperado |
|---|---|
| Archivo correcto y anuncio listo | Intersticial, cerrar -> JSON completo |
| Catálogo correcto y anuncio listo | Intersticial, cerrar -> JSON completo |
| Sin fill, SDK caído, sin red de anuncios | JSON directamente |
| Anuncio falla tras empezar | JSON una vez; sin quedarse en pantalla negra |
| Doble callback / rotación de pantalla | Una navegación, una oportunidad |
| Operación fallida, incompleta o cancelada | Ningún intersticial |
| Exportar o copiar JSON | Libre de anuncios |
| Resultado de miles de líneas | Íntegro, sin truncamientos |
| App en background al finalizar | No aparece publicidad por encima de otra app |
| Scroll de catálogo | Anuncios correctamente etiquetados, sin clic accidental ni conteo duplicado |
| SDK sin consentimiento requerido | No se inicializa donde se prohíba; el descifrado sigue funcionando |
| Apagar publicidad desde el panel | No nuevas oportunidades; resultados intactos |
| AAB Google Play vs APK Telegram | Verificar configuración y aprobación por canal |
| APK Offline | No contiene SDK, adaptadores ni configuraciones publicitarias |
| Inspector de red / logs | Ningún dato del descifrado llega a proveedores |

## 10. Entregables y secuencia

**A0:** Esta documentación, sin código ni credenciales nuevas.  
**A1:** Cuenta aprobada, app registrada, privacy/consent, App Key y unidades de prueba.  
**A2:** Integración LevelPlay en Online (Gradle/Manifest/R8) y tests con anuncios de prueba.  
**A3:** Intersticial tras éxito, resultado conservado, cero anuncios en errores.  
**A4:** Native catálogo mediante red aprobada compatible; UX, accesibilidad y lifecycle.  
**A5:** Panel de configuración y kill switch; integración ads.txt y métricas.  
**A6:** QA de dos APK y liberación escalonada, monitorización y rollback.

**Prohibido declarar monetización habilitada en producción sin aprobación de la red, pruebas reales y APK firmada validada.**