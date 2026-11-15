package com.ghostdeveloper.spdecode

import com.google.gson.JsonObject
import com.google.gson.JsonParser

/** Display adapter. Report bytes from Cloud remain unchanged in storage. */
internal data class ApkReportBlock(val title:String,val language:String,val content:String) {
    val markdown:String get() {
        if (language=="markdown") return content
        val fence=if (content.contains("```")) "```\u0060" else "```"
        return fence+language+"\n"+content+"\n"+fence
    }
}

internal object ApkReportMarkdown {
    fun blocks(report:String):List<ApkReportBlock> {
        val source=report.trim()
        val root=runCatching { JsonParser.parseString(source) }.getOrNull()
        if (root==null || !root.isJsonObject) {
            return listOf(ApkReportBlock("Report",if (source.startsWith("#")||source.startsWith("```")) "markdown" else "text",report))
        }
        // Preserve the exact received JSON: the native viewer already exposes
        // readable indexed lines, and reparsing/pretty-printing duplicates RAM.
        val result=mutableListOf(ApkReportBlock("JSON","json",report))
        val artifacts=root.asJsonObject.get("artifacts")
        if (artifacts!=null && artifacts.isJsonArray) {
            artifacts.asJsonArray.forEachIndexed { index,entry ->
                if (!entry.isJsonObject) return@forEachIndexed
                val item:JsonObject=entry.asJsonObject
                val body=item.get("content")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }
                    ?.asString ?: return@forEachIndexed
                val mime=item.get("mimeType")?.takeIf { it.isJsonPrimitive }?.asString.orEmpty()
                val lang=when(mime) {
                    "application/json"->"json"
                    "text/markdown"->"markdown"
                    else->"text"
                }
                val title=item.get("name")?.takeIf { it.isJsonPrimitive && it.asJsonPrimitive.isString }
                    ?.asString?.take(80) ?: "Artifact ${index+1}"
                result.add(ApkReportBlock(title,lang,body))
            }
        }
        return result
    }
}
