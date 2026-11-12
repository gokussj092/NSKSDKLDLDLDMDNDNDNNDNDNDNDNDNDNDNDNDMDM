package com.ghostdeveloper.spdecode

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.net.HttpURLConnection
import java.net.URL

/** Public, unsigned store catalog is DISPLAY DATA only. Prices must be re-quoted
 * by the authenticated server before any real checkout. USD is the only client
 * currency here; absent prices never become locally invented prices. */
internal data class StoreCreditOffer(
    val planId:String, val credits:Int, val priceCents:Int, val available:Boolean
)
internal data class StoreApiOffer(
    val planId:String, val days:Int, val priceCents:Int, val available:Boolean
)
internal data class NativeStoreCatalog(
    val creditPacks:List<StoreCreditOffer>,
    val apiPlans:List<StoreApiOffer>,
    val creditsVersion:Int,
    val apiVersion:Int,
    val authEnabled:Boolean,
    val live:Boolean
) {
    companion object {
        private const val URL_CATALOG="https://spdecode.xyz/api/store/catalog"
        suspend fun load():NativeStoreCatalog?=withContext(Dispatchers.IO) {
            var connection:HttpURLConnection?=null
            try {
                connection=URL(URL_CATALOG).openConnection() as HttpURLConnection
                connection.instanceFollowRedirects=false
                connection.connectTimeout=8000
                connection.readTimeout=8000
                connection.setRequestProperty("Accept","application/json")
                connection.setRequestProperty("Cache-Control","no-cache")
                if(connection.responseCode!=200)return@withContext null
                if(!connection.contentType.orEmpty().lowercase().startsWith("application/json"))
                    return@withContext null
                val payload=connection.inputStream.use{stream->
                    // A tiny bounded catalog; never parse unbounded remote JSON.
                    val bytes=stream.readNBytes(128*1024+1)
                    if(bytes.size>128*1024)return@withContext null
                    bytes.toString(Charsets.UTF_8)
                }
                parse(payload)
            } catch(_:Exception){null}
            finally{connection?.disconnect()}
        }
        internal fun parse(payload:String):NativeStoreCatalog? {
            if(payload.length>128*1024)return null
            val root=runCatching{JSONObject(payload)}.getOrNull()?:return null
            val products=root.optJSONArray("products")?:return null
            var credits=emptyList<StoreCreditOffer>()
            var api=emptyList<StoreApiOffer>()
            var creditVersion=0
            var apiVersion=0
            for(i in 0 until minOf(products.length(),25)){
                val product=products.optJSONObject(i)?:continue
                val id=product.optString("id")
                if(id!="analysis-credits" && id!="api-ip")continue
                val plans=product.optJSONArray("plans")?:continue
                if(id=="analysis-credits")creditVersion=product.optInt("version",0)
                else apiVersion=product.optInt("version",0)
                for(j in 0 until minOf(plans.length(),30)){
                    val plan=plans.optJSONObject(j)?:continue
                    val term=plan.optString("id")
                    val price=plan.optJSONObject("prices")?.optInt("USD",0)?:0
                    if(price !in 100..1_000_000 || term.isBlank())continue
                    val enabled=plan.optBoolean("available",false)
                    if(id=="analysis-credits"){
                        val amount=plan.optInt("credits",0)
                        if(amount !in 1..100 || term!="${amount}c")continue
                        credits=credits+StoreCreditOffer(term,amount,price,enabled)
                    }else{
                        val days=plan.optInt("days",0)
                        if(days !in 1..3650 || term !in setOf("base","1m","2m","3m","6m","12m"))
                            continue
                        api=api+StoreApiOffer(term,days,price,enabled)
                    }
                }
            }
            return NativeStoreCatalog(credits.distinctBy{it.planId}.sortedBy{it.credits},
                api.distinctBy{it.planId}.sortedBy{it.days},
                creditVersion,apiVersion,root.optBoolean("authEnabled",false),
                root.optBoolean("live",false))
        }
    }
}
