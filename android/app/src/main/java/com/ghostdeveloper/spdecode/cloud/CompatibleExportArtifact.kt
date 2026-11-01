package com.ghostdeveloper.spdecode.cloud

import android.util.Base64
import org.json.JSONObject
import java.security.MessageDigest

/** Prepared server bytes, never opening credentials or a presentation-derived JSON. */
class CompatibleExportArtifact private constructor(
    val suffix:String,
    val sourceSha256:String,
    val decodedSha256:String,
    val sha256:String,
    val sizeBytes:Int,
    private val encoded:String,
) {
    val targetAppName:String get()=targets.getValue(suffix).second
    /** Preserve the source basename; SAF still lets the user choose a destination. */
    fun filenameFor(original:String):String = CompatibleExportFilename.forSource(original,suffix)

    val filename:String get()="config-SP-DECODE.$suffix"
    fun bytes():ByteArray=Base64.decode(encoded,Base64.NO_WRAP)
    fun matches(rawText:String)=decodedSha256==digest(rawText.toByteArray(Charsets.UTF_8))
    override fun toString()="CompatibleExportArtifact(suffix=$suffix,sizeBytes=$sizeBytes)"

    fun toJson():JSONObject=JSONObject()
        .put("status","ready").put("schemaVersion",1).put("profile",PROFILE)
        .put("targetAppId",targets.getValue(suffix).first).put("targetAppName",targetAppName)
        .put("extension", ".$suffix").put("filename",filename)
        .put("mimeType","application/octet-stream").put("sourceSha256",sourceSha256)
        .put("decodedSha256",decodedSha256).put("sha256",sha256).put("sizeBytes",sizeBytes)
        .put("dataBase64",encoded).put("protections",JSONObject()
            .put("filePasswordRequired",false).put("hwidRequired",false).put("recipientPrivateKeyRequired",false))

    companion object {
        const val PROFILE="original-app-open-v1"
        const val MAX_BYTES=1024*1024
        val targets=mapOf("hc" to ("http-custom" to "HTTP Custom"),
            "dark" to ("dark-tunnel" to "Dark Tunnel"),
            "ehi" to ("http-injector" to "HTTP Injector"),
            "hat" to ("ha-tunnel-plus" to "HA Tunnel Plus"),
            "npvs" to ("npv-tunnel" to "NPV Tunnel"))
        fun digest(bytes:ByteArray):String=MessageDigest.getInstance("SHA-256")
            .digest(bytes).joinToString(""){"%02x".format(it)}

        fun parse(value:JSONObject?,suffix:String,rawText:String,expectedSource:String?=null):CompatibleExportArtifact? {
            if(value==null||value.optString("status")!="ready")return null
            require(suffix in targets)
            val keys=setOf("status","schemaVersion","profile","targetAppId","targetAppName","extension",
                "filename","mimeType","sourceSha256","decodedSha256","sha256","sizeBytes","dataBase64","protections")
            require(value.keys().asSequence().toSet()==keys)
            require(value.get("schemaVersion")==1&&value.getString("profile")==PROFILE)
            require(value.getString("targetAppId")==targets.getValue(suffix).first&&
                value.getString("targetAppName")==targets.getValue(suffix).second&&
                value.getString("extension")==".$suffix"&&value.getString("filename")=="config-SP-DECODE.$suffix"&&
                value.getString("mimeType")=="application/octet-stream")
            val source=value.getString("sourceSha256")
            val decoded=value.getString("decodedSha256")
            val checksum=value.getString("sha256")
            require(listOf(source,decoded,checksum).all{it.matches(Regex("[a-f0-9]{64}"))})
            require(expectedSource==null||expectedSource==source)
            require(decoded==digest(rawText.toByteArray(Charsets.UTF_8)))
            val size=value.get("sizeBytes")
            require(size is Int&&size in 1..MAX_BYTES)
            val encoded=value.getString("dataBase64")
            require(encoded.length<=((MAX_BYTES+2)/3)*4&&encoded.length%4==0&&
                encoded.matches(Regex("[A-Za-z0-9+/]+={0,2}")))
            val bytes=Base64.decode(encoded,Base64.NO_WRAP)
            try {
                require(bytes.size==size&&digest(bytes)==checksum&&
                    Base64.encodeToString(bytes,Base64.NO_WRAP)==encoded)
                if(suffix=="npvs")require(bytes.take(6).toByteArray().contentEquals("NPVO1\n".toByteArray()))
                if(suffix=="dark")require(bytes.take(13).toByteArray().contentEquals("darktunnel://".toByteArray()))
            } finally {bytes.fill(0)}
            val p=value.getJSONObject("protections")
            val flags=setOf("filePasswordRequired","hwidRequired","recipientPrivateKeyRequired")
            require(p.keys().asSequence().toSet()==flags&&flags.all{p.get(it)==false})
            return CompatibleExportArtifact(suffix,source,decoded,checksum,size,encoded)
        }
    }
}

/** Only negotiated, fixed application metadata can enable a file request. */
internal class CompatibleExportCatalog private constructor(val suffixes:Set<String>) {
    companion object {
        fun parse(root:JSONObject?):CompatibleExportCatalog {
            if(root==null)return CompatibleExportCatalog(emptySet())
            require(root.get("schemaVersion")==1&&root.getString("profile")==CompatibleExportArtifact.PROFILE)
            require(root.get("enabled") is Boolean&&root.get("revision") is Int&&root.getInt("revision")>=0)
            require(root.getString("minimumAppVersion").matches(Regex("[0-9]+\\.[0-9]+\\.[0-9]+")))
            require(root.getInt("maxArtifactBytes") in 1..CompatibleExportArtifact.MAX_BYTES)
            val array=root.getJSONArray("formats")
            require(array.length() in 0..CompatibleExportArtifact.targets.size)
            val suffixes=HashSet<String>()
            for(i in 0 until array.length()) {
                val item=array.getJSONObject(i)
                val suffix=item.getString("suffix")
                val target=CompatibleExportArtifact.targets[suffix]?:error("Unknown target")
                require(suffixes.add(suffix)&&item.getString("targetAppId")==target.first&&item.getString("name")==target.second)
                require(item.getString("banner")==if(suffix in setOf("hc","ehi"))"spdecode-html" else "none")
            }
            require(root.getBoolean("enabled")||suffixes.isEmpty())
            return CompatibleExportCatalog(if(root.getBoolean("enabled"))suffixes else emptySet())
        }
    }
}

