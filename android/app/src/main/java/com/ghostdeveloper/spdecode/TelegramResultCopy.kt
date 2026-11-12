package com.ghostdeveloper.spdecode

/**
 * Clipboard-only share envelope. JSON file exports must remain valid, pure JSON;
 * decoded raw text in encrypted history is never modified.
 *
 * Telegram's triple-backtick JSON code fence is intended for messages sent with
 * Markdown formatting enabled. Attribution is deliberately outside the JSON.
 */
object TelegramResultCopy {
    /** Telegram handles are optional. Remove all leading @ signs and reject markup. */
    fun normalizeUsername(input:String):String? {
        val handle=input.trim().trimStart('@')
        if(handle.isEmpty())return ""
        return if(Regex("[A-Za-z0-9_]{5,32}").matches(handle))"@"+handle else null
    }

    fun clipboard(view: DecodeView, format: ResultExport, displayDate: String,
                  attribution: String? = null): String {
        val header = buildString {
            append("// Decoded by SP-DECODE\n")
            append("// Date: ").append(displayDate).append('\n')
            append("// Powered by Ghost Developer")
            if(!attribution.isNullOrBlank())append("\n// ").append(attribution)
        }
        return when (format) {
            ResultExport.JSON -> buildString {
                val json = if(ResultOutputWriter.isLarge(view.rawText))java.io.StringWriter().also{ResultOutputWriter.write(view.rawText,view.extension,ResultExport.JSON,it)}.toString().trimEnd() else ResultJsonDisplay.render(view.rawText, view.extension, false).trimEnd()
                append(header).append("\n\n")
                append("```json\n")
                append(json).append('\n')
                append("```")
            }
            ResultExport.ORIGINAL ->
                header + "\n\n" + view.rawText
            ResultExport.ORDERED -> {
                val ordered=if(ResultOutputWriter.isLarge(view.rawText))java.io.StringWriter().also{
                    ResultOutputWriter.write(view.rawText,view.extension,ResultExport.ORDERED,it)
                }.toString() else view.document.structured
                if(attribution.isNullOrBlank())ordered else "// "+attribution+"\n\n"+ordered
            }
        }
    }
}
