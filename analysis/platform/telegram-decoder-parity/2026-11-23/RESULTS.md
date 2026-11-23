# Resultado de las pruebas del adaptador de Telegram

Estado PARTIAL. La integración del repositorio pasó pruebas offline con el
motor compartido. La ejecución en el servicio real de Telegram requiere
instalar esta revisión y probarla con una cuenta autorizada.

| Comprobación | Resultado |
| --- | --- |
| Inventario | 282 extensiones de Cloud, incluidas las 246 anteriores del bot. Los 282 lectores referenciados existen. |
| Textos | 76 prefijos usan el despachador compartido. Los handlers Telegram de SSC, Dark Tunnel, TLS, HAPP y V2Box conservan sus entradas dedicadas. |
| HTTP Custom rev. 57 | Los fixtures de build 564 y exportación 565 coinciden campo por campo. El resultado parcial conserva el aviso. |
| HCCFG protegido | El flujo privado avanza de HWID a contraseña y responde al documento original. El remitente y la respuesta deben coincidir con la sesión. |
| XVEON | Resultado equivalente para archivos y enlaces sintéticos, incluida una entrada que requiere contraseña. |
| Regresiones históricas | 87 pruebas dirigidas pasaron. |
| Adaptador, XU, XVEON y registro Cloud | 31 pruebas pasaron con 14 subpruebas. Una prueba opcional con un enlace real fue excluida. |

La prueba inicial del archivo HCCFG con ambas credenciales observó
`HWID_REQUIRED` primero. La prueba posterior verifica que el bot sigue
la secuencia real del motor hasta `PASSWORD_REQUIRED` y acepta el perfil
con ambas credenciales sintéticas.

El despacho no añade variantes que el motor Cloud no implemente. Los
esquemas HCCFG que siguen pendientes conservan el estado que documenta el
expediente del build 934.
