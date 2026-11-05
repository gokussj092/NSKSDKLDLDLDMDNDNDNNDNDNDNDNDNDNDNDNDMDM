package com.ghostdeveloper.spdecode.cloud
import org.json.JSONObject
internal class ServerVpnSecureCache {
    val values=mutableMapOf<String,ByteArray>()
    fun read(name:String)=values[name]?.clone()
    fun write(name:String,value:ByteArray){values[name]=value.clone()}
    fun delete(name:String){values.remove(name)}
    fun pruneDownloadCache(discard:Boolean=false){if(discard)values.clear()}
}
internal class CloudDecodeClient(val fixture:JSONObject) {
    class Failure(val code:String,val httpStatus:Int):java.io.IOException(code)
    var interrupt=true
    val requested=mutableListOf<String>()
    suspend fun catalogManifest(knownVersion:Int,snapshotId:String?):JSONObject {
        require(knownVersion==0);if(snapshotId!=null)require(snapshotId==fixture.getJSONObject("manifest").getString("snapshotId"))
        return fixture.getJSONObject("manifest")
    }
    suspend fun catalogChunk(input:JSONObject):JSONObject {
        val key=input.getString("objectHash")+":"+input.getInt("chunkIndex")
        requested.add(key)
        if(interrupt&&input.getInt("chunkIndex")==1)throw Failure("SERVICE_UNAVAILABLE",503)
        return fixture.getJSONObject("chunks").getJSONObject(key)
    }
}
