package com.ghostdeveloper.spdecode.cloud

import org.json.JSONArray
import org.json.JSONObject

/** Only an intact HC document with its one explicitly preserved legacy slot. */
internal object CloudHcPartialResult {
    fun allows(response:JSONObject):Boolean {
      return runCatching {
        if(response.optString("format")!="hc" || response.opt("isPartial")!=true)return false
        val warnings=response.optJSONArray("warnings")?:return false
        if(warnings.length()!=1 || warnings.optString(0)!="HC_UNRESOLVED_FIELDS")return false
        val report=response.optJSONObject("structuredJson")?:return false
        val config=report.optJSONObject("Config")?:return false
        if(config.length()!=32 || config.keys().asSequence().any { config.opt(it) !is String } ||
            !config.optString("psiphon").matches(Regex("[0-9a-fA-F]{32}")) ||
            report.optJSONObject("Protections")==null)return false
        val metadata=report.optJSONObject("Metadata")?:return false
        if(metadata.optJSONObject("envelope")?.opt("verCfg")!=57 ||
            metadata.optJSONObject("config")?.opt("verApp") !in listOf(564,565))return false
        val unresolved=report.optJSONArray("UnresolvedFields")?:return false
        if(unresolved.length()!=1)return false
        val field=unresolved.optJSONObject(0)?:return false
        if(field.length()!=3 || field.opt("index")!=17 || field.optString("field")!="psiphon" ||
            field.optString("status")!="encrypted_unresolved")return false
        same(JSONObject(response.getString("rawText")),report)
      }.getOrDefault(false)
    }

    private fun same(a:Any?,b:Any?):Boolean = when {
        a is JSONObject && b is JSONObject -> a.length()==b.length() &&
            a.keys().asSequence().all { b.has(it) && same(a.opt(it),b.opt(it)) }
        a is JSONArray && b is JSONArray -> a.length()==b.length() &&
            (0 until a.length()).all { same(a.opt(it),b.opt(it)) }
        else -> a==b
    }
}
