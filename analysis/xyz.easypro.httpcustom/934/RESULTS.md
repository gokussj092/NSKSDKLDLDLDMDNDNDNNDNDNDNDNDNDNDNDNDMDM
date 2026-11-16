# Resultado actual: PARTIAL — 6/9 JSON completos autenticados

La [revisión con el script aportado](REVISION_2026_11_15.md) autentica las seis
muestras 12/n15, incluidas ambas con contraseña, con dos implementaciones
SHA/AEAD y siete capas por muestra. n16, n18 y wrapper 9 siguen pendientes.
El lector de producción permanece intacto. La matriz siguiente conserva el
resultado histórico anterior a recibir y corregir el nuevo script.

El [seguimiento de los tres métodos pendientes](FOLLOWUP_METHODS_2026_11_15.md)
confirma el cálculo público HC2, recupera parámetros RSA del inicializador
original y traza n16 hasta operación 2/familia 5. **No añade descifrados reales.**
Los 14 tests actuales del expediente pasan, incluido un oráculo RSA JCE
independiente y controles de rechazo; no sustituyen una prueba de importación
original ni autentican los tres archivos pendientes. Evidencia sin material
privado en `generated/followup_validation.json`.

## Checkpoint histórico: PENDING — ningún payload nuevo descifrado

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
