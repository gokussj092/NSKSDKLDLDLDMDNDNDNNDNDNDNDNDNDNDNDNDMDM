package com.ghostdeveloper.spdecode.cloud

import android.util.Base64
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.security.MessageDigest

/** Payload-byte progress, authenticated manifest, encrypted restart journal.
 * Each request uses a fresh existing native HPKE/session exchange. No URLs or keys.
 */
internal class CatalogSnapshotDownload(private val client:CloudDecodeClient,private val vault:ServerVpnSecureCache) {
    private fun hash(bytes:ByteArray)=MessageDigest.getInstance("SHA-256").digest(bytes).joinToString(""){"%02x".format(it)}
    private fun decode(text:String):ByteArray {
        require(text.length<=9*1024*1024)
        val bytes=Base64.decode(text,Base64.NO_WRAP)
        require(Base64.encodeToString(bytes,Base64.NO_WRAP)==text)
        return bytes
    }
    private fun key(prefix:String,hash:String,index:Int?=null)=prefix+hash.take(48)+(index?.let{"-$it"}?:"")
    suspend fun download(knownVersion:Int,onTransfer:((Long,Long)->Unit)?):JSONObject {
        vault.pruneDownloadCache()
        val pending=vault.read("chunk-journal")?.let {runCatching{JSONObject(it.toString(Charsets.UTF_8))}.getOrNull()}
        val reply=client.catalogManifest(knownVersion,pending?.optString("snapshotId")?.takeIf{it.matches(Regex("[a-f0-9]{64}"))})
        val id=reply.getString("snapshotId")
        val manifestBytes=decode(reply.getString("manifestBase64"))
        require(manifestBytes.size<=256*1024 && hash(manifestBytes)==id && reply.getString("manifestHash")==id)
        val manifest=JSONObject(manifestBytes.toString(Charsets.UTF_8))
        require(manifest.getString("protocol")=="catalog-chunks-v1" && manifest.getInt("schemaVersion")==1)
        require(manifest.getInt("catalogVersion")>=knownVersion && manifest.getLong("validUntil")>System.currentTimeMillis())
        val objects=manifest.getJSONArray("objects");require(objects.length() in 2..501)
        val seen=HashSet<String>();var logical=0L;var pendingBytes=0L
        data class ObjectPlan(val doc:JSONObject,val cached:Boolean)
        val plans=ArrayList<ObjectPlan>()
        for(n in 0 until objects.length()) {
            val obj=objects.getJSONObject(n);val sha=obj.getString("sha256");val length=obj.getInt("byteLength")
            require(sha.matches(Regex("[a-f0-9]{64}")) && seen.add(sha) && length in 1..6*1024*1024)
            require(obj.getInt("chunkSize")==256*1024 && obj.getInt("chunkCount")==((length+262143)/262144))
            val chunks=obj.getJSONArray("chunks");require(chunks.length()==obj.getInt("chunkCount"))
            for(i in 0 until chunks.length())require(chunks.getString(i).matches(Regex("[a-f0-9]{64}")))
            require(if(n==0)obj.getString("type")=="metadata"&&length<=2*1024*1024 else obj.getString("type")=="icon")
            logical+=length;require(logical<=64L*1024*1024)
            val bytes=vault.read(key("object-",sha));val cached=bytes!=null&&bytes.size==length&&hash(bytes)==sha
            if(!cached)pendingBytes+=length
            plans.add(ObjectPlan(obj,cached))
        }
        require(logical==manifest.getLong("totalLogicalBytes"))
        vault.write("chunk-journal",JSONObject().put("snapshotId",id).put("validUntil",manifest.getLong("validUntil")).toString().toByteArray())
        var verified=0L;onTransfer?.invoke(0L,pendingBytes)
        var metadata:JSONObject?=null
        for(plan in plans) {
            currentCoroutineContext().ensureActive()
            val obj=plan.doc;val sha=obj.getString("sha256");val length=obj.getInt("byteLength")
            val bytes=if(plan.cached)vault.read(key("object-",sha))!! else {
                val output=ByteArrayOutputStream(length)
                for(i in 0 until obj.getInt("chunkCount")) {
                    currentCoroutineContext().ensureActive()
                    val expected=obj.getJSONArray("chunks").getString(i);val size=minOf(262144,length-i*262144)
                    val cacheKey=key("part-",sha,i)
                    var part=vault.read(cacheKey)?.takeIf{it.size==size&&hash(it)==expected}
                    if(part==null) {
                        val request=JSONObject().put("snapshotId",id).put("manifestHash",id).put("objectHash",sha).put("chunkIndex",i)
                        var response:JSONObject
                        try{response=client.catalogChunk(request)}catch(e:CloudDecodeClient.Failure) {
                            if(e.code!="CATALOG_LEASE_EXPIRED")throw e
                            // A new session never reuses old HPKE state; reauthorize this immutable snapshot.
                            val renewed=client.catalogManifest(knownVersion,id);require(renewed.getString("snapshotId")==id)
                            response=client.catalogChunk(request)
                        }
                        require(response.getString("snapshotId")==id&&response.getString("manifestHash")==id&&response.getString("objectHash")==sha&&response.getInt("chunkIndex")==i&&response.getInt("byteLength")==size&&response.getString("sha256")==expected)
                        part=decode(response.getString("dataBase64"));require(part.size==size&&hash(part)==expected)
                        vault.write(cacheKey,part)
                    }
                    output.write(part);verified+=part.size;onTransfer?.invoke(verified,pendingBytes)
                }
                output.toByteArray().also {require(it.size==length&&hash(it)==sha);vault.write(key("object-",sha),it)}
            }
            require(bytes.size==length&&hash(bytes)==sha)
            if(obj.getString("type")=="metadata")metadata=JSONObject(bytes.toString(Charsets.UTF_8))
            else vault.write("icon-"+sha.take(56),bytes)
        }
        val result=metadata?:error("CATALOG_SCHEMA_INVALID")
        require(result.getInt("catalogVersion")==manifest.getInt("catalogVersion"))
        val apps=result.getJSONArray("apps");for(i in 0 until apps.length())require(seen.contains(apps.getJSONObject(i).getString("iconSha256")))
        result.put("snapshotId",id)
        // Repository validates formats and all icon references, then commits catalog atomically.
        return result
    }
    fun committed(){vault.delete("chunk-journal")}
}
