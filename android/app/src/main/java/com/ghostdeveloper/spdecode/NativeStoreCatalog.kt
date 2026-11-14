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
    val planId:String, val days:Int, val priceCents:Int, val available:Boolean,
    val prices:Map<String,Int> = mapOf("USD" to priceCents),val providers:List<String> = emptyList()
)
internal data class StoreAdFreeOffer(
    val priceCents:Int,val version:Int,val available:Boolean,val providers:List<String>,
    val prices:Map<String,Int> = mapOf("USD" to priceCents)
)
internal data class NativeStoreCatalog(
    val adFree:StoreAdFreeOffer?,
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
                    val out=java.io.ByteArrayOutputStream()
                    val chunk=ByteArray(4096)
                    while(true){
                        val read=stream.read(chunk)
                        if(read<0)break
                        if(out.size()+read>128*1024)return@withContext null
                        out.write(chunk,0,read)
                    }
                    out.toString(Charsets.UTF_8.name())
                }
                parse(payload)
            } catch(_:Exception){null}
            finally{connection?.disconnect()}
        }
        private fun prices(plan:JSONObject):Map<String,Int> =
            listOf("USD","MXN","EUR").mapNotNull { currency->
                val amount=plan.optJSONObject("prices")?.optInt(currency,0)?:0
                if(amount in 100..1_000_000)currency to amount else null
            }.toMap()
        private fun providers(product:JSONObject):List<String> {
            val array=product.optJSONArray("providers")?:return emptyList()
            return (0 until minOf(array.length(),8)).mapNotNull { i->
                array.optString(i).takeIf { it in setOf("stripe","paypal","mercadopago") }
            }.distinct()
        }
        internal fun parse(payload:String):NativeStoreCatalog? {
            if(payload.length>128*1024)return null
            val root=runCatching{JSONObject(payload)}.getOrNull()?:return null
            val products=root.optJSONArray("products")?:return null
            var ads:StoreAdFreeOffer?=null
            var credits=emptyList<StoreCreditOffer>()
            var api=emptyList<StoreApiOffer>()
            var creditVersion=0
            var apiVersion=0
            for(i in 0 until minOf(products.length(),25)){
                val product=products.optJSONObject(i)?:continue
                val id=product.optString("id")
                if(id !in setOf("analysis-credits","api-ip","ads-free"))continue
                if(id=="ads-free"){
                    val plan=product.optJSONArray("plans")?.optJSONObject(0)
                    if(plan?.optString("id")=="base" && plan.optInt("days")==30){
                        val amounts=prices(plan)
                        val methods=providers(product)
                        val cents=amounts["USD"]?:amounts.values.firstOrNull()?:0
                        if(cents in 100..1_000_000){
                            ads=StoreAdFreeOffer(cents,product.optInt("version",0),
                                plan.optBoolean("available",false)&&methods.isNotEmpty(),
                                methods,amounts)
                        }
                    }
                    continue
                }
                val plans=product.optJSONArray("plans")?:continue
                if(id=="analysis-credits")creditVersion=product.optInt("version",0)
                else apiVersion=product.optInt("version",0)
                for(j in 0 until minOf(plans.length(),30)){
                    val plan=plans.optJSONObject(j)?:continue
                    val term=plan.optString("id")
                    val amounts=prices(plan)
                    val price=if(id=="analysis-credits") amounts["USD"]?:0 else amounts["USD"]?:amounts.values.firstOrNull()?:0
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
                        api=api+StoreApiOffer(term,days,price,enabled&&providers(product).isNotEmpty(),amounts,providers(product))
                    }
                }
            }
            return NativeStoreCatalog(ads,
                credits.distinctBy{it.planId}.sortedBy{it.credits},
                api.distinctBy{it.planId}.sortedBy{it.days},
                creditVersion,apiVersion,root.optBoolean("authEnabled",false),
                root.optBoolean("live",false))
        }
    }
}
