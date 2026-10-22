# FlexNet — compatibilidad B42 y B46

Actualización para FlexNet **V 2.4 / build 46**, conservando V 2.3 / B42 y los
formatos históricos. El nombre de carpeta/módulo B42 se mantiene para no romper
imports. El punto de entrada `decoders/Python/flex.py` admite `.flex`/`.flexnet`
v1–v6; los dos lanzadores `flexnet_b42.py` atienden v5/v6 y los catálogos anteriores.
No se añade un proveedor remoto ni se modifica el catálogo Server VPN.

- v1–v4: se conservan los 30 materiales y el algoritmo existente.
- v5 offline de generación 1: conserva HKDF-SHA256 y las dos capas AES-GCM.
  En B46 ese contenedor interno se exporta dentro de v6.
- v5 online: admite mínimo build 46 y una clave de contenido autorizada.
- v6: abre AES-GCM con la clave autorizada del setup offline y después el v5
  offline interior. Esta clave de Android Keystore no está en el APK ni archivo.
- Campos protegidos `customSni`/`proxyPayload`: autentica FLXFLD, binding y GCM.
  `rawProperties` conserva todos los valores originales, incluidos los aliases.
  `protectedFields` contiene los campos reales y `decodedProperties` la vista
  completa con esos valores abiertos. La vista normalizada de `flex.py` usa
  los valores reales. Un binding/tag inválido produce error, sin usar el alias.

## Uso

Python >=3.10 y `pip install -r requirements.txt`. Desde la raíz del repositorio:

```bash
python decoders/Python/flex.py perfil_antiguo.flex
python decoders/Python/flexnet_b42.py perfil.flex --inspect
python decoders/Python/flex.py online.flex --file-key-file clave_contenido.bin
python decoders/Python/flexnet_b42.py online.flex --file-key-file clave_contenido.bin -o resultado.json
python decoders/Python/flex.py offline_v6.flex --offline-key-file clave_setup.bin
```

Las claves son 32 bytes binarios o 64 caracteres hexadecimales. Son claves
legítimas de esa exportación/setup, no contraseñas adivinadas ni el `wrappedGrant`.
`run(data, file_key=...)` y `run(data, offline_key=...)` aceptan los mismos datos.
El script es offline y no fabrica identidades, retos o concesiones del servidor.
Los imports, rutas Cloud existentes, catálogos FBS1/RSA y extensiones se mantienen.

**Muestra recibida `free (1).flex`:** FLXCFG v5 online, mínimo B46, 1388 bytes.
Ahora se reconoce correctamente, pero **su contenido sigue sin recuperarse**:
falta su clave de contenido del flujo oficial de autorización. Devuelve
`ONLINE_AUTH_REQUIRED`, sin JSON parcial. La compatibilidad criptográfica nueva
se comprueba con vectores JDK sintéticos y una ejecución del campo nativo ARM64;
no se presenta esta muestra real como descifrada. Ver `TESTING.md` y
[el análisis B46](../../../../docs/FLEXNET_V2_4_B46.md).
