package com.ghostdeveloper.spdecode.cloud

import android.content.Context
import com.ghostdeveloper.spdecode.ServerVpnNewBadges
import com.ghostdeveloper.spdecode.parity.AndroidDecoderCatalog
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
    private val newBadges=ServerVpnNewBadges(context)
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

    /** A strict, read-only catalogue: never accept executable routes or arbitrary URLs. */
    internal fun validateFormats(record:JSONObject?):List<AndroidDecoderCatalog.Format> {
        require(record!=null && record.optInt("formatsSchemaVersion",-1)==1)
        val detection=record.getJSONObject("formatDetection")
        require(detection.getString("rule")=="longest-filename-suffix" &&
            detection.getBoolean("caseInsensitive") &&
            detection.getString("separator")==".")
        val array=record.getJSONArray("formats")
        require(array.length() in 1..1024 && record.getInt("formatCount")==array.length())
        val formats=ArrayList<AndroidDecoderCatalog.Format>(array.length())
        val seen=HashSet<String>()
        val supportedFields=setOf("password","hwid","publicKey")
        val keys=setOf("suffix","name","kind","offlineSupported","cloudSupported","credentialFields")
        var last:String?=null
        for(i in 0 until array.length()) {
            val entry=array.getJSONObject(i)
            require(entry.keys().asSequence().toSet()==keys)
            val suffix=entry.getString("suffix")
            val name=entry.getString("name")
            require(suffix.matches(Regex("^[\\p{L}\\p{N}_.-]{1,64}$")) &&
                suffix==suffix.lowercase(java.util.Locale.ROOT) && seen.add(suffix))
            require(name.isNotBlank() && name==name.trim() && name.length<=120)
            require(entry.getString("kind")=="file" &&
                entry.getBoolean("cloudSupported"))
            entry.getBoolean("offlineSupported")
            val credentials=entry.getJSONArray("credentialFields")
            require(credentials.length()<=3)
            val credentialNames=(0 until credentials.length()).map { j ->
                credentials.getString(j)
            }
            require(credentialNames.toSet().size==credentialNames.size &&
                credentialNames.all { it in supportedFields })
            if(last!=null) require(last.length>suffix.length ||
                (last.length==suffix.length && last<suffix))
            last=suffix
            // The server never chooses a local native engine. All remote
            // entries use the already allowlisted Cloud format route.
            formats.add(AndroidDecoderCatalog.Format(suffix,name,"cloud_server_only",
                false,"C8",cloudSupported=true,credentialFields=credentialNames.toSet()))
        }
        return formats
    }

    /** Public text/cloud-import declarations only; never accept routes or URLs. */
    internal fun validateTextFormats(record:JSONObject?):List<CloudTextRoute> {
        if(record?.has("textSchemaVersion")!=true)return emptyList() // old VPS snapshot
        require(record.optInt("textSchemaVersion",-1)==1)
        val array=record.getJSONArray("textFormats")
        require(array.length() in 1..256 && record.getInt("textCount")==array.length())
        val seen=HashSet<String>()
        val routes=ArrayList<CloudTextRoute>(array.length())
        val keys=setOf("prefix","name","suffix","kind")
        for(index in 0 until array.length()){
            val entry=array.getJSONObject(index)
            require(entry.keys().asSequence().toSet()==keys)
            val prefix=entry.getString("prefix")
            val name=entry.getString("name")
            val suffix=entry.getString("suffix")
            val kind=entry.getString("kind")
            // Prefix syntax must agree with the VPS validator: no relative
            // paths, dot segments, URLs or arbitrarily executable routes.
            require(prefix.length in 4..64 &&
                !prefix.startsWith("http://",ignoreCase=true) &&
                !prefix.startsWith("https://",ignoreCase=true) &&
                prefix.matches(Regex("""^(?:[A-Za-z0-9][A-Za-z0-9-]{1,62}://[A-Za-z0-9/_-]*|[A-Za-z0-9][A-Za-z0-9-]{1,62}:|[A-Za-z0-9][A-Za-z0-9-]{1,62}\.)$""")) &&
                seen.add(prefix.lowercase(java.util.Locale.ROOT)))
            require(name.length in 1..80 && name==name.trim())
            require(suffix.matches(Regex("^[a-z0-9_-]{1,32}$")))
            require(kind=="text" || kind=="cloud")
            routes.add(CloudTextRoute(prefix,name,suffix,kind))
        }
        return routes
    }

    suspend fun cachedTextFormats():List<CloudTextRoute> =
        withContext(Dispatchers.IO) {
            try { validateTextFormats(stored()) }catch(_:Exception){emptyList()}
        }

    private fun verifiedFormats(record:JSONObject?):List<AndroidDecoderCatalog.Format> =
        try { validateFormats(record) } catch (_:Exception) { emptyList() }

    /** Encrypted snapshot only. Never fetch automatically when sync is disabled. */
    suspend fun cachedFormats():List<AndroidDecoderCatalog.Format> =
        withContext(Dispatchers.IO) { verifiedFormats(stored()) }

    fun hasCachedFormats():Boolean = verifiedFormats(stored()).isNotEmpty()

    suspend fun cached():List<ServerVpnApp> = withContext(Dispatchers.IO) {
        verifiedApps(stored()).also { apps ->
            newBadges.observeCatalog(apps.map { it.id }.toSet())
        }
    }

    fun currentVersion():Int = stored()?.optInt("catalogVersion",0)?:0

    /** VPS-only hint; verified HTTPS metadata and encrypted cache are authoritative. */
    suspend fun refreshIfDue(force:Boolean=false,announcedVersion:Int=0,
        onProgress:((Int)->Unit)?=null):List<ServerVpnApp> = mutex.withLock {
        withContext(Dispatchers.IO) {
            val previous=stored()
            val available=verifiedApps(previous)
            val cachedFormats=verifiedFormats(previous)
            // Establish the previous verified catalog as the local baseline before
            // incorporating newly published entries (also from background sync).
            newBadges.observeCatalog(available.map { it.id }.toSet())
            val now=System.currentTimeMillis()
            val last=previous?.optLong("checkedAtMillis",0L)?:0L
            val previousVersion=previous?.optInt("catalogVersion",0)?:0
            val urgent=announcedVersion>previousVersion
            if(!force && !urgent && available.isNotEmpty() && cachedFormats.isNotEmpty() && last>0 && now>=last &&
                now-last<versionCheckMillis) return@withContext available
            try {
                // Manual refresh still uses the version contract; metadata changes must bump version.
                val knownVersion=if(available.isEmpty() || cachedFormats.isEmpty())0 else previousVersion
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
                // Reject an incomplete format snapshot before touching the encrypted cache.
                val remoteFormats=validateFormats(remote)
                require(remoteFormats.isNotEmpty())
                val remoteTexts=validateTextFormats(remote)
                require(!remote.has("textSchemaVersion") || remoteTexts.isNotEmpty())
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
                    // Percentage of catalog app records and hash-verified icons
                    // processed, not a fake HTTP byte-level download progress.
                    onProgress?.invoke(minOf(99,(i+1)*100/array.length()))
                }
                // Write validated icons first, then atomically activate metadata.
                for((id,data) in candidates)vault.write(id,data)
                val fresh=JSONObject()
                    .put("catalogVersion",remoteVersion)
                    .put("checkedAtMillis",now)
                    .put("apps",array)
                    .put("formatsSchemaVersion",remote.getInt("formatsSchemaVersion"))
                    .put("formatCount",remote.getInt("formatCount"))
                    .put("formatDetection",remote.getJSONObject("formatDetection"))
                    .put("formats",remote.getJSONArray("formats"))
                if(remote.has("textSchemaVersion")) fresh
                    .put("textSchemaVersion",remote.getInt("textSchemaVersion"))
                    .put("textCount",remote.getInt("textCount"))
                    .put("textFormats",remote.getJSONArray("textFormats"))
                vault.write("catalog",fresh.toString().toByteArray(Charsets.UTF_8))
                onProgress?.invoke(100)
                verifiedApps(fresh).ifEmpty { available }.also { apps ->
                    newBadges.observeCatalog(apps.map { it.id }.toSet())
                }
            }catch(error:CancellationException){throw error}
             catch(_:Exception){available}
        }
    }
}
