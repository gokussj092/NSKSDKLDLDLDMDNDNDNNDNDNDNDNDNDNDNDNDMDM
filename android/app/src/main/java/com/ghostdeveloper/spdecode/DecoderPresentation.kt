package com.ghostdeveloper.spdecode

/** Decoder output always retained as-is; structured/JSON are separate views. */
data class DecodeView(
    val filename:String,
    val extension:String,
    val rawText:String,
    val fileBytes:Int,
    val id:String=java.util.UUID.randomUUID().toString(),
    val savedAtMillis:Long=System.currentTimeMillis(),
    val favorite:Boolean=false,
    val compatibleExport:com.ghostdeveloper.spdecode.cloud.CompatibleExportArtifact?=null,
) {
    val document:ResultDocument by lazy(LazyThreadSafetyMode.PUBLICATION) {
        ResultPresentation.parse(rawText,extension)
    }
    val redactedText:String get()=RedactionPolicy.mask(rawText)
    val fields:List<Pair<String,String>> get()=document.fields.map{it.path to it.value}
}

/** Preview-only redaction; does not remove or rewrite the original data. */
object RedactionPolicy {
    private val line=Regex("""^(\s*(?:│\[[^]]+]\s*)?([^:\r\n]{1,150})\s*:\s*)([^\r\n]*)$""")
    fun isSensitive(name:String)=ResultPresentation.isCredential(name)
    fun mask(input:String):String=input.lineSequence().joinToString("\n"){row->
        val m=line.matchEntire(row)
        if(m!=null&&isSensitive(m.groupValues[2]))m.groupValues[1]+"••••••••" else row
    }
}
