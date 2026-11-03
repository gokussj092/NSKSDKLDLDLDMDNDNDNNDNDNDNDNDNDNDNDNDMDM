# Halcon build1391 — investigación pendiente de catálogo real

Fecha local: 2026-11-02, America/Tijuana. Rama de trabajo:
`fix/http-jireh-current-method`; base consultada
`b165b8fe4d9cae280b9fe88cbaf3d1a68e435698`.

## Observaciones verificadas

- La URL aportada contiene `com.halcon.connect`. La ficha pública descargada
  por GET muestra **HALCON RAMOS Conectividad**, desarrollador HALCON RAMOS y
  actualización15/09/2026. La búsqueda web no devolvió una entrada exacta útil;
  no se interpreta eso como ausencia de la aplicación.
- APKPure redirige la página al nombre anterior y anuncia4.1.4/code1391 con
  fecha30/10/2026. Se descargó la variante ARM64. Las fechas de tienda y espejo
  difieren: no se certifica que sea la última versión oficial.
- Androguard confirma en el manifiesto real `com.halcon.connect`, **Halcon R Net**,
  versionName4.1.4/versionCode1391. XAPK:34644705 bytes,
  SHA256 `f90ef42a4c610afd35eb5ea496cccfc3fb3ded473cf8949d8a1056a51b879077`.
  Base:12884825 bytes, SHA256
  `bd5a259b37427914a44a3e49f7ad4f9a8b22823285f6dc9d94f4e809036b8aac`.
  Inventario completo de splits en `generated/input_inventory.json`.
- Se leyó el certificado V2 del APK; SHA256 DER público:
  `c00947e011a92e6200f7bb708d7f06665df10f3ebe4775db890f12789948e051`.
  No se descargó una copia desde Play para contrastar esa firma ni se certifica
  autenticidad del espejo a partir de su propia etiqueta de verificación.
- Biblioteca ARM64 `libnative-security.so`:1475672 bytes; SHA256
  `e42ea94147e04390f27c35f1d2e067e10c4c5a170f4a70b3ac59f56fc18c04d0`.
- `L2.a` es el actualizador: POST principal con hash y timestamp en cabeceras
  y cuerpo de formulario; GET de respaldo si falla el principal. El resultado
  se valida con `NativeSecurity.nativeDecrypt` y el campo `version` antes de
  guardar. No confundir estos destinos con APIs de VIP, pagos, tiempo o premios.
- El valor de `getDefaultConfig` en0xec91c referencia0x44d17: **`{}`**.
  Es un objeto vacío, no un catálogo inicial de servidores.
- El GET de respaldo realmente ejecutado devolvió **HTTP404**, text/plain,
  14 bytes; hash del cuerpo
  `d5558cd419c8d46bdc958064cb97f963d1ea793866414c025906ec15033512ed`.
  No contiene catálogo ni JSON descifrado. Evidencia: `generated/backup.summary.json`.

## Interpretación estática y prueba sintética

La clase `halcon.vip.vpn.util.AESCrypt` muestra caracteres de bloque que
representan nibbles de bytes Base64. El sobre es nonce12 + ciphertext + tag16;
AES256-GCM sin AAD, clave SHA256 de la contraseña UTF8 que entrega el llamador.
`envelope_candidate.py` implementa esa interpretación con rechazo estricto de
entrada inválida y sin fallback a JSON plano. Conserva el JSON entero.

La rutina nativa0xe89ac concatena siete fragmentos de8 bytes y uno de9,
recuperados mediante XOR incremental desde0x77, con la identidad de firma
calculada por0xe4498. La receta candidata usa SHA256(Base64 sin saltos del
certificado DER) en hexadecimal mayúsculo. La rama de host depende de comparar
esa identidad con una constante nativa; la muestra no coincide y selecciona
producción. `recover.py` restringe los offsets a los hashes exactos y escribe
la receta solamente en un directorio privado0600. No se publican sus valores.

`generateApiSignature`0xecc48 concatena timestamp decimal con un material
del cliente y llama a la rutina SHA2560xe6220. Se reconstruyó estáticamente
la forma de la petición. No se afirma que el servidor la acepte.

El oráculo independiente escrito con Java/JCA generó y reabrió un fixture
sintético; Python recupera exactamente todo el objeto de referencia, incluidos
Unicode, campos desconocidos, nulos y booleanos. Esto comprueba la interpretación
de la primitiva; **no autentica un catálogo real ni los campos nativos internos**.

## Intentos y fallos conservados

1. El inspector compartido sobre el XAPK falló `Cannot identify base APK`:
   el archivo base se llama `com.halcon.connect.apk`, no `base.apk`. El mismo
   inspector sobre la entrada base explícita confirmó la identidad y extrajo
   los dos DEX. No se modificó el inspector compartido.
2. JADX1.5.6: classes.dex terminó exit3/con22 errores; classes2.dex exit0.
   El actualizador y AESCrypt proceden del segundo. La salida parcial del primero
   no se usa como evidencia de compilación ni de descifrado.
3. Una lectura inicial de0x16fb50 como datos de archivo falló: es una variable
   inicializada en memoria. Se localizaron las referencias y el inicializador
   en0xf0038. El fallo no se interpretó como una clave ausente.
4. `probe_v1.py` falló antes de red por usar `Request.method`; se corrigió a
   `get_method()` en v2. Ambas revisiones se conservan en `tools/history/`.
5. **Auto-review bloqueó la validación del POST autenticado** porque enviaría
   una firma derivada de material de la APK a un tercero sin autorización
   explícita. No hay respuesta principal verificada ni se reintentó por otra vía.
   `probe.py` ahora exige un indicador adicional de autorización; ese indicador
   nunca sustituye la aprobación del propietario.
6. `javac` no está en PATH. `java` sí incluye `jdk.compiler`: el oráculo se
   ejecutó en modo fuente con OpenJDK17.0.20, sin instalar otro JDK.

## Alcance y continuidad

Estado **PENDING**. No hay módulo operativo en `decoders/Python/apps/`, ficha,
icono publicado, broker, registro worker ni incremento de catálogo para Halcon.
No se modifican Android, versión/firma, controles existentes, novedades, main
ni VPS. No se lanzaron workflows manualmente.

Para cerrar: obtener permiso explícito para la petición del actualizador o una
respuesta auténtica obtenida por un flujo autorizado; autenticar el sobre real,
recuperar y comparar íntegramente campos y esquema frente al original, y después
implementar/probar el proveedor. Los tests sintéticos y los offsets recuperados
no sustituyen esos pasos. La integración existente permanece intacta.
