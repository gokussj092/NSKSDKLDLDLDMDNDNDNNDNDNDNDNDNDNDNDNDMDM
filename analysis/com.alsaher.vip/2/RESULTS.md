# Resultados

Estado: VERIFIED_REAL para descarga/descifrado Cloud; integrado en código.

| Escenario | Resultado |
| --- | --- |
| APK aportada | Paquete/versión/build y hash confirmados; ZIP íntegro |
| Incluido |9.9.9:4 servidores,4 HTTP,1 SSL; JSON completo igual a Java/CLI/worker |
| GET remoto real con UA original | HTTP200,80552 bytes;9.9.58:14 servidores,3 HTTP,9 SSL |
| Campos del remoto |76 cifrados,33 distintos; documento entero igual a Java/CLI/worker |
| Python |9 pruebas correctas; fixtures sintéticos independientes |
| Node |38 pruebas correctas, incluidas regresiones de Halcon y broker/contrato |
| Node real | REMOTE_NETWORK_DENIED del ejecutor; VPS pendiente |
| Replay Node | Bytes y resultado reales, HTTP simulado; contrato completo correcto |
| Android | Sin cambios, sin compilar ni esperar workflows |

Hash remoto:
`b8900e20f929652f9c1da615b19aba0dcd83d804a1a9006a5575bd10ebf085f3`.
Hash incluido:
`fdd5e77b9161b6a17bf9b1287eba694d9237a97c6d6dd389b232963ae725fb76`.
Los dos bytesets, versiones y recuentos se registran separados. No se insertan
datos VPN reales en Git ni se declaran certificados exportadores o nuevos formatos.
La fuente no exige nuevos secretos de backend.
