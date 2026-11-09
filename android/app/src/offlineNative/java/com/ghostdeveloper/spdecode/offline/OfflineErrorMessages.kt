package com.ghostdeveloper.spdecode.offline

import java.util.Locale

internal data class OfflineUiError(
    val title: String,
    val description: String,
)

internal fun readableDecodeError(reason: String, suffix: String, language: String): OfflineUiError {
    val spanish = if (language == "system") Locale.getDefault().language == "es" else language == "es"
    val label = suffix.takeIf { it.isNotBlank() }?.let { "." + it.lowercase(Locale.ROOT) }
        ?: if (spanish) "desconocido" else "unknown"
    fun message(esTitle:String,esBody:String,enTitle:String,enBody:String) =
        OfflineUiError(if(spanish) esTitle else enTitle,if(spanish) esBody else enBody)
    val code=reason.uppercase(Locale.ROOT)
    if(code=="UNSUPPORTED_OFFLINE_FORMAT"||code=="UNSUPPORTED_FORMAT"||code=="INVALID_EXTENSION")
        return message("Archivo no compatible",
            "Este tipo de archivo ($label) todavía no se admite. Comprueba que hayas seleccionado el archivo original.",
            "Unsupported file","This file type ($label) is not supported. Select an original configuration file.")
    if(code=="FILE_TOO_LARGE")return message("Archivo demasiado grande",
        "Este archivo supera el límite permitido de 4 MB para importaciones sin conexión.",
        "File too large","The file exceeds the 4 MB limit for offline imports.")
    if(code=="FILE_UNAVAILABLE"||code=="SECURITY_EXCEPTION"||code=="FILE_NOT_FOUND")
        return message("No se pudo abrir el archivo",
            "La aplicación no pudo leerlo. Comprueba que esté descargado y vuelve a compartirlo desde Telegram, WhatsApp o Archivos.",
            "Could not open file","The file could not be read. Download it and share it again from Telegram, WhatsApp or Files.")
    if(code=="EMPTY_FILE")return message("Archivo vacío",
        "El archivo no contiene información. Selecciona otro archivo.",
        "Empty file","The file does not contain any data. Choose another file.")
    if(code=="NPV_RECIPIENT_MISMATCH"||code=="RECIPIENT_MISMATCH"||
       code=="PRIVATE_KEY_REQUIRED")
        return message("Se requiere la identidad original",
            "Este archivo está protegido para otra identidad. Para abrirlo necesitas la clave privada correspondiente a la clave pública usada al crearlo. Una clave generada ahora no sirve para descifrar archivos de otro usuario.",
            "Original identity required",
            "This file is protected for another identity. You need the private key matching the public key used when it was created. A newly generated key cannot open files encrypted for another user.")
    if(code=="NPV_RECIPIENT_V1_UNSUPPORTED"||code=="NPV_PROTECTION_UNSUPPORTED")
        return message("Protección NPV no compatible",
            "Este archivo NPV utiliza una modalidad de protección que esta versión todavía no admite. No significa necesariamente que esté dañado.",
            "Unsupported NPV protection",
            "This NPV file uses a protection mode not supported by this version. It is not necessarily corrupted.")
    if(code.contains("UNSUPPORTED")||code=="HAT_UNSUPPORTED_VERSION"||
       code=="HC_UNRECOGNIZED_FORMAT"||
       code=="HC_INVALID_V3"||code=="HC_INVALID_MAGIC"||code=="HC_UNSUPPORTED_SCHEMA"||
       code=="EHI_UNRECOGNIZED_FORMAT"||code=="EHI_INVALID_HEADER"||
       code=="HAT_UNRECOGNIZED_DOCUMENT")
        return message("Versión no compatible",
            "El archivo $label pertenece a una versión o variante que esta aplicación todavía no puede descifrar. Comprueba el formato y la versión de la aplicación que lo creó.",
            "Unsupported version",
            "This $label file uses a version or variant that this app cannot decode yet. Check the format and version of the app that created it.")
    if(code=="PASSWORD_REQUIRED"||code=="HWID_REQUIRED"||code=="HWID_PASSWORD_REQUIRED")
        return message("Archivo protegido",
            "Se necesitan las credenciales originales con las que se protegió este archivo.",
            "Protected file","The original credentials used to protect this file are required.")
    if(code=="AUTH_FAILED"||code=="NPV_INVALID_CREDENTIALS"||
       code=="HC_INVALID_CREDENTIAL"||code=="HC_INVALID_PASSWORD")
        return message("No se pudo verificar la contraseña",
            "La contraseña, la identidad o los datos de protección no coinciden con este archivo. Comprueba los datos originales.",
            "Credentials do not match",
            "The password, identity or protection details do not match this file. Verify the original details.")
    if(code=="INVALID_JSON"||code=="HAT_INVALID_DOCUMENT"||
       code=="DARK_INVALID_JSON_ENVELOPE"||code.startsWith("NETMOD_")||
       code.startsWith("DARK_INVALID_")||code.startsWith("HAT_INVALID_"))
        return message("Archivo incorrecto o dañado",
            "No se ha encontrado una configuración válida para $label. El contenido podría estar incompleto, alterado o tener una versión no compatible.",
            "Invalid or damaged file",
            "No valid $label configuration was found. The data may be incomplete, altered or use an unsupported version.")
    if(code=="INVALID_TEXT"||code=="UNSUPPORTED_TEXT")
        return message("Texto no compatible",
            "Pega un enlace completo de un formato admitido. No se puede procesar un texto incompleto.",
            "Unsupported text","Paste a complete link in a supported format. Incomplete text cannot be processed.")
    return message("No se pudo descifrar",
        "No fue posible obtener el contenido de $label. Comprueba que el archivo esté completo y sea compatible.",
        "Could not decode",
        "The content of $label could not be decoded. Check that the file is complete and compatible.")
}
