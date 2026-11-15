# Resultado: PENDING — ningún payload nuevo descifrado

| Prueba real | Cantidad | Resultado |
| --- | ---: | --- |
| HCCFG 12/n15 | 6 | HCX4 exterior autenticado; interior pendiente |
| HCCFG 12/n16, contraseña y HWID | 1 | HCX4 exterior autenticado; interior pendiente |
| HCCFG 13/n18, HWID y protección extra | 1 | HCX4 exterior autenticado; activación/interior pendientes |
| Wrapper 9 con ID de acceso | 1 | Certificado público identificado; unwrap/interior pendientes |
| JSON completos autenticados de build 934 | **0/9** | **No se habilita soporte nuevo** |
| Enlace eprdv.link | 1 | HTTP 200 HTML; ninguna configuración descargada |

Las credenciales reales aportadas se usaron localmente y por stdin. No se
concluye que sean incorrectas: el lector rechaza el esquema antes de usarlas.
Las dos hipótesis experimentales HCCFG 12 también fallan con esos datos.

Validación ejecutada con CPython 3.12.14 y dependencias fijadas:

- 3/3 tests del expediente: metadatos autenticados, ausencia de material
  privado en diagnósticos y rechazo de corrupción/truncado.
- 29/29 regresiones existentes: `tests.test_http_custom_899`,
  `tests.test_hc_sip_new_variants`, `tests.test_cloud_c2_hc`,
  `tests.test_hc_legacy57`.
- Los tests sintéticos prueban esas propiedades; **no** prueban descifrado
  nuevo, importación física, activación ni conexión VPN.
- JADX: 55 errores generales. Inicializadores ELF: llamadas de entorno
  `getauxval` y `__system_property_get` no ejecutadas en la primera receta.
  Pruebas JNI limitadas por llamadas Android faltantes y un bucle de
  inicialización; no se consideran una activación ni un oráculo válido.

El método operativo permanece intacto. Este expediente es un checkpoint de
investigación, no un cambio desplegable de compatibilidad. No se compiló APK,
no se desplegó VPS ni se efectuó merge a main.
