package com.ghostdeveloper.spdecode.cloud

import android.content.Context
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.util.Locale

/** Read-only, user-facing release notes; content never executes and contains no URLs. */
data class CloudNewsItem(val id:String,val type:String,val title:String,val description:String)
data class CloudNewsNotice(val version:Int,val title:String,val subtitle:String,
    val publishedAt:String,val items:List<CloudNewsItem>)

internal class CloudWhatsNewRepository(context:Context,private val client:CloudDecodeClient) {
    private val vault=ServerVpnSecureCache(context)
    private val mutex=Mutex()
    private val supported=setOf("en","es","ar","fa","fr","id","ru","de","pt-BR",
        "tr","vi","hi","ja","it")

    fun language(selected:String):String {
        val raw=if(selected=="system") Locale.getDefault().toLanguageTag() else selected
        val code=raw.substringBefore('-').lowercase(Locale.ROOT)
        val chosen=if(code=="pt")"pt-BR" else code
        return if(chosen in supported)chosen else "en"
    }

    private fun safeText(value:String,max:Int):Boolean =
        value.isNotBlank() && value.length<=max &&
            !value.any { it=='<' || it=='>' || it.code<32 && it!='\n' }

    private fun parse(document:JSONObject):CloudNewsNotice? {
        val version=document.optInt("version",0)
        val title=document.optString("title")
        val subtitle=document.optString("subtitle")
        val date=document.optString("publishedAt")
        if(version !in 1..999999999||!safeText(title,100)||
            !safeText(subtitle,250)||!date.matches(Regex("\\d{4}-\\d{2}-\\d{2}")))
            return null
        val rows=document.optJSONArray("items")?:return null
        if(rows.length() !in 1..12)return null
        val ids=mutableSetOf<String>()
        val items=ArrayList<CloudNewsItem>(rows.length())
        for(i in 0 until rows.length()){
            val row=rows.optJSONObject(i)?:return null
            val id=row.optString("id")
            val type=row.optString("type")
            val name=row.optString("title")
            val description=row.optString("description")
            if(!id.matches(Regex("[a-z0-9-]{3,48}"))||!ids.add(id)||
                type !in setOf("feature","support","improvement","fix")||
                !safeText(name,90)||!safeText(description,320))return null
            items.add(CloudNewsItem(id,type,name,description))
        }
        return CloudNewsNotice(version,title,subtitle,date,items)
    }

    /** Only a fully validated snapshot is stored in the device-bound encrypted vault. */
    suspend fun latestUnseen(selected:String,lastSeen:Int):CloudNewsNotice? = mutex.withLock {
        withContext(Dispatchers.IO) {
            val locale=language(selected)
            val cached=try{
                vault.read("whats-new")?.toString(Charsets.UTF_8)?.let(::JSONObject)
            }catch(_:Exception){null}
            val stored=if(cached?.optString("locale")==locale)cached?.let(::parse) else null
            val knownVersion=stored?.version ?: 0
            var latest=stored
            try{
                val remote=client.whatsNew(knownVersion,locale)
                val remoteVersion=remote.optInt("version",0)
                if(remoteVersion>=knownVersion && remoteVersion in 1..999999999){
                    if(!remote.optBoolean("unchanged",false)){
                        val incoming=parse(remote)
                        if(incoming!=null && incoming.version==remoteVersion &&
                            remote.optString("locale")==locale){
                            val raw=remote.toString().toByteArray(Charsets.UTF_8)
                            if(raw.size<=16384){
                                vault.write("whats-new",raw)
                                latest=incoming
                            }
                        }
                    }
                }
            }catch(error:CancellationException){throw error}
             catch(_:Exception){ /* Network failure: use previous verified encrypted snapshot. */ }
            latest?.takeIf { it.version>lastSeen }
        }
    }
}
