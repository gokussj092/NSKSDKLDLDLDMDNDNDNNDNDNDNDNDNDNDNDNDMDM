package com.ghostdeveloper.spdecode

/**
 * Clipboard-only share envelope. JSON file exports must remain valid, pure JSON;
 * decoded raw text in encrypted history is never modified.
 *
 * Telegram's triple-backtick JSON code fence is intended for messages sent with
 * Markdown formatting enabled. Attribution is deliberately outside the JSON.
 */
object TelegramResultCopy {
    private const val HEADER_CREDITS = "// Credits: Ghost Developer"

    fun clipboard(view: DecodeView, format: ResultExport, displayDate: String): String {
        val header = buildString {
            append("// Decoded by SP-DECODE\n")
            append("// Date: ").append(displayDate).append('\n')
            append("// Powered by Ghost Developer\n")
            append(HEADER_CREDITS)
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
            ResultExport.ORDERED -> if(ResultOutputWriter.isLarge(view.rawText))java.io.StringWriter().also{ResultOutputWriter.write(view.rawText,view.extension,ResultExport.ORDERED,it)}.toString() else view.document.structured
        }
    }
}
