package com.ghostdeveloper.spdecode.cloud

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.util.Base64
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import java.security.MessageDigest

data class ServerVpnApp(
    val id:String,
    val name:String,
    val icon:Bitmap,
    val decodeEnabled:Boolean,
)

/** All app images are the original, hash-checked PNGs supplied by the API. */
internal class ServerVpnCatalogRepository(
    context: Context,
    private val client: CloudDecodeClient,
) {
    private val vault=ServerVpnSecureCache(context)
    private val mutex=Mutex()
    // Only a lightweight version check, not a full catalog download.
    private val versionCheckMillis=15*60_000L

    private fun digest(data:ByteArray):String =
        MessageDigest.getInstance("SHA-256").digest(data).joinToString("") { "%02x".format(it) }

    private fun stored():JSONObject? = try {
        vault.read("catalog")?.toString(Charsets.UTF_8)?.let(::JSONObject)
    }catch (_:Exception){null}

    private fun image(bytes:ByteArray):Bitmap? {
        if(!ServerVpnIconPolicy.isPng(bytes))return null
        // Read dimensions without allocating pixels: a tiny PNG can expand
        // into a dangerously large bitmap on a low-memory Android device.
        val bounds=BitmapFactory.Options().apply { inJustDecodeBounds=true }
        BitmapFactory.decodeByteArray(bytes,0,bytes.size,bounds)
        if(bounds.outWidth<=0 || bounds.outHeight<=0)return null
        val options=BitmapFactory.Options().apply {
            inScaled=false
            inSampleSize=ServerVpnIconPolicy.sampleSize(bounds.outWidth,bounds.outHeight)
        }
        return BitmapFactory.decodeByteArray(bytes,0,bytes.size,options)
            ?.takeIf { it.width>0 && it.height>0 }
    }

    private fun verifiedApps(record:JSONObject?):List<ServerVpnApp> {
        if(record==null || record.optInt("catalogVersion",0)<1)return emptyList()
        val array=record.optJSONArray("apps")?:return emptyList()
        if(array.length() !in 1..100)return emptyList()
        val seen=mutableSetOf<String>()
        val apps=ArrayList<ServerVpnApp>(array.length())
        for(index in 0 until array.length()) {
            val app=array.optJSONObject(index)?:return emptyList()
            val id=app.optString("id")
            val name=app.optString("name")
            val checksum=app.optString("iconSha256")
            if(!id.matches(Regex("[a-z0-9-]{1,48}")) || !seen.add(id) ||
                name.isBlank() || name.length>80 ||
                !checksum.matches(Regex("[0-9a-f]{64}"))) return emptyList()
            val bytes=vault.read("icon-$id")?:return emptyList()
            if(digest(bytes)!=checksum)return emptyList()
            val bitmap=image(bytes)?:return emptyList()
            apps.add(ServerVpnApp(id,name,bitmap,app.optBoolean("decodeEnabled",false)))
        }
        return apps
    }

    suspend fun cached():List<ServerVpnApp> = withContext(Dispatchers.IO) {
        verifiedApps(stored())
    }

    fun currentVersion():Int = stored()?.optInt("catalogVersion",0)?:0

    /** VPS-only hint; verified HTTPS metadata and encrypted cache are authoritative. */
    suspend fun refreshIfDue(force:Boolean=false,announcedVersion:Int=0):List<ServerVpnApp> = mutex.withLock {
        withContext(Dispatchers.IO) {
            val previous=stored()
            val available=verifiedApps(previous)
            val now=System.currentTimeMillis()
            val last=previous?.optLong("checkedAtMillis",0L)?:0L
            val previousVersion=previous?.optInt("catalogVersion",0)?:0
            val urgent=announcedVersion>previousVersion
            if(!force && !urgent && available.isNotEmpty() && last>0 && now>=last &&
                now-last<versionCheckMillis) return@withContext available
            try {
                // Manual refresh still uses the version contract; metadata changes must bump version.
                val knownVersion=if(available.isEmpty())0 else previousVersion
                val remote=client.serverVpnCatalog(knownVersion)
                if(remote.optBoolean("unchanged",false)) {
                    if(available.isEmpty() || remote.optInt("catalogVersion")!=knownVersion)
                        throw IllegalStateException("Invalid catalog version response")
                    previous!!.put("checkedAtMillis",now)
                    vault.write("catalog",previous.toString().toByteArray(Charsets.UTF_8))
                    return@withContext available
                }
                val remoteVersion=remote.optInt("catalogVersion",0)
                if(remoteVersion<1 || remoteVersion<previousVersion)
                    throw IllegalStateException("Catalog rollback")
                val array=remote.optJSONArray("apps")?:throw IllegalStateException("Missing app list")
                if(array.length() !in 1..100)throw IllegalStateException("Invalid app count")
                val candidates=ArrayList<Pair<String,ByteArray>>()
                val seen=mutableSetOf<String>()
                for(i in 0 until array.length()) {
                    val entry=array.optJSONObject(i)?:throw IllegalStateException("Invalid entry")
                    val id=entry.optString("id")
                    val name=entry.optString("name")
                    val checksum=entry.optString("iconSha256")
                    if(!id.matches(Regex("[a-z0-9-]{1,48}")) || !seen.add(id) ||
                        name.isBlank() || name.length>80 ||
                        !checksum.matches(Regex("[0-9a-f]{64}")) ||
                        entry.optString("iconMimeType")!="image/png")
                        throw IllegalStateException("Invalid app metadata")
                    var bytes=vault.read("icon-$id")
                    if(bytes==null || digest(bytes)!=checksum || image(bytes)==null) {
                        val response=client.serverVpnIcon(id)
                        if(response.optString("id")!=id || response.optString("sha256")!=checksum ||
                            response.optString("mimeType")!="image/png")
                            throw IllegalStateException("Icon metadata mismatch")
                        val base64=response.getString("contentBase64")
                        bytes=Base64.decode(base64,Base64.NO_WRAP)
                        if(Base64.encodeToString(bytes,Base64.NO_WRAP)!=base64 ||
                            digest(bytes)!=checksum || image(bytes)==null)
                            throw IllegalStateException("Icon digest mismatch")
                        candidates.add("icon-$id" to bytes)
                    }
                }
                // Write validated icons first, then atomically activate metadata.
                for((id,data) in candidates)vault.write(id,data)
                val fresh=JSONObject()
                    .put("catalogVersion",remoteVersion)
                    .put("checkedAtMillis",now)
                    .put("apps",array)
                vault.write("catalog",fresh.toString().toByteArray(Charsets.UTF_8))
                verifiedApps(fresh).ifEmpty { available }
            }catch(error:CancellationException){throw error}
             catch(_:Exception){available}
        }
    }
}
