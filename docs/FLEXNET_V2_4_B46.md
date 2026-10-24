# FlexNet V 2.4 B46 — actualización compatible

Continuación del 24 de octubre: [captura de importación autorizada](FLEXNET_V2_4_AUTHORIZED_IMPORT.md),
layout de concesión de 117 bytes, CLI `--grant-capture` y 87 casos nativos de
binding. Las dos muestras online reales **siguen pendientes de su captura**.
La [tercera muestra v6 offline](FLEXNET_V2_4_V6_SAMPLE.md) también se probó:
requiere la época offline del Keystore o capturar el v5 interior de la app.

Paquete `com.flexnet.tunnel`, V 2.4, versionCode 46. PR #96, misma rama
`feat/austroplus-vpn-13-0-1-decoders`. Se amplía el lector B42 existente,
sin duplicarlo ni eliminar versiones anteriores. Ver
[README](../decoders/Python/apps/FlexNet_B42/README.md) y
[comprobaciones](../decoders/Python/apps/FlexNet_B42/TESTING.md).

## Cambios recuperados del APK

`config.y.b` abre v5 online con `file-unlock`; `config.A` usa retos firmados con
`flexnet.v5.request` y `VpnRouteBridge.transport` desenvuelve la concesión con
`flexnet.v5.route`, identidades de Android Keystore. La clave aleatoria del
archivo no puede deducirse de su identificador, hash o los materiales legacy.
Se mantiene la entrada de clave autorizada `--file-key-file`; también se admite
una captura de la concesión ya desenvuelta durante la importación oficial.

El modo offline B46 añade un contenedor **FLXCFG v6**, modo 1, suite 1, mínimo
build >=44: cabecera de 45 bytes (magic6/version/mode/suite/build4/key-id16/
nonce12/longitud4). AES-256-GCM autentica toda la cabecera con la clave legítima
del setup almacenada en Keystore (`config.B.i` y `d.w`). El plaintext es un v5
offline de generación 1, no XML/gzip directo. `--offline-key-file` permite abrir
esa capa y el lector anterior verifica después ambas capas GCM y gzip del v5.

La raíz de wrapping de generación 1 permanece igual: XOR de dos bloques de
32 bytes en offsets **0xa98c** / **0xa9ac** del `libvpnbridge.so` arm64 B46.
No se reemplaza la raíz B42 ni los 30 materiales de v1–v4.

`config.j` añade `file.routeFields=1` y `file.routeData` con estructura
`{"v":1,"fields":{"customSni":{"a":"alias","c":"Base64"}}}`; admite también
`proxyPayload`. Los valores visibles pueden ser aliases, no los campos reales.

Cada `c` es Base64 canónico de un sobre **FLXFLD**:

| Offset | Tamaño | Contenido |
| --- | --- | --- |
| 0 | 8 | FLXFLD, versión 1, suite 1 |
| 8 | 4 | Generación/build fijo 43, big-endian |
| 12 | 32 | Salt HKDF |
| 44 | 12 | Nonce GCM |
| 56 | 4 | Longitud del ciphertext más tag |
| 60 | variable | Ciphertext y tag GCM de 16 bytes |

Binding UTF-8: `FlexNet/inner-field/v1` + byte cero + nombre + `|` + alias.
HKDF-SHA256 usa la raíz de wrapping, el salt y el info
`FlexNet/inner-field/v1/generation-1` + binding. AES-256-GCM autentica cabecera60
+ binding. Se verifican estructura, generación, longitudes, alias y tag antes
de exponer plaintext. `rawProperties` conserva el XML original; `protectedFields`
y `decodedProperties` exponen los datos abiertos. No se devuelve el alias como
resultado exitoso si su sobre está alterado.

## Estado de la muestra y validación

`free (1).flex` es v5 **online**, mínimo B46. El lector ya supera el antiguo
rechazo por build 42, pero devuelve `ONLINE_AUTH_REQUIRED`: **no se descifró la
muestra sin su clave autorizada**. Esta limitación es criptográfica, no una
solicitud de permisos adicionales. No se fabrica una atestación o concesión.

**22 pruebas específicas aprobadas**, paridad de XML con vectores JDK nuevos,
regresión v1–v5 y una comprobación del campo original ARM64 frente a JDK/Python.
La ruta Cloud de `.flex` procesa el vector v5 interior con campos protegidos;
las claves online/setup se proporcionan solamente en la API Python/CLI existente,
no mediante nuevos campos públicos del gateway. No se anuncia descifrado online
automático, cambio de catálogo Server VPN, despliegue o novedades publicadas.

APK SHA-256: `bb30b8aa5bb4207c97f19f752eeefb2fb87b417b6e491864c8508cce4c6ae5cb`.
Biblioteca arm64 SHA-256: `a1779083ed5418eedd1ff70ea10e729745dfc2baac27ec2441fc517ff80098bb`.
