package com.ghostdeveloper.spdecode
import com.ghostdeveloper.spdecode.cloud.*
import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.StringWriter
import javax.crypto.spec.SecretKeySpec
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import com.ghostdeveloper.spdecode.results.NativeResultEngine
fun main(args:Array<String>)=runBlocking {
    val fixture=JSONObject(java.io.File(args[0]).readText());val client=CloudDecodeClient(fixture);val cache=ServerVpnSecureCache()
    cache.write("catalog","old-active-snapshot".toByteArray())
    val downloader=CatalogSnapshotDownload(client,cache);var failed=false
    try{downloader.download(0,null)}catch(_:CloudDecodeClient.Failure){failed=true};check(failed)
    check(cache.read("catalog")!!.decodeToString()=="old-active-snapshot")
    client.interrupt=false;client.requested.clear();val progress=mutableListOf<Pair<Long,Long>>()
    val metadata=CatalogSnapshotDownload(client,cache).download(0){received,total->progress.add(received to total)}
    check(metadata.getInt("catalogVersion")==73);check(client.requested.size==2);check(client.requested.none{it.endsWith(":0")})
    check(progress.last().first==progress.last().second);check(progress.zipWithNext().all{(a,b)->a.first<=b.first})
    downloader.committed();check(cache.read("chunk-journal")==null)
    for(size in listOf(8000,20000,50000)) {
        val raw="[\r\n"+(0 until size).joinToString(",\r\n"){"{\"id\":$it,\"name\":\"demo🌎\"}"}+"\r\n]"
        val out=StringWriter();ResultOutputWriter.write(raw,"vpn",ResultExport.JSON,out);check(out.toString()==raw)
        NativeResultEngine.open(raw).use { doc ->
            var offset=0
            while(true){val page=doc.page(0,offset,false);offset=page.getInt("next");if(!page.getBoolean("hasMore"))break}
            check(offset==size)
            val exported=ByteArrayOutputStream();doc.exportOriginal(exported);check(exported.toString("UTF-8")==raw)
        }
        val summary=DecodeView("fixture.json","json",raw,raw.length).historySummary()
        check(summary.metadataOnly&&summary.rawText.isEmpty()&&summary.compatibleExport==null)
        val ordered=StringWriter();ResultOutputWriter.write(raw,"vpn",ResultExport.ORDERED,ordered)
        check(ordered.toString().contains(" [${size}] › id: ${size-1}"))
        val key=SecretKeySpec(ByteArray(32){it.toByte()},"AES");val record=ByteArrayOutputStream()
        ResultSnapshotCodec.write("fixture-id",raw,JSONObject().put("version",4),key,record)
        val bytes=record.toByteArray();check(ResultSnapshotCodec.read("fixture-id",ByteArrayInputStream(bytes),key).second==raw)
        check(ResultSnapshotCodec.inspect("fixture-id",ByteArrayInputStream(bytes),key).getJSONObject("snapshot").getInt("byteLength")==raw.toByteArray().size)
        for(corrupt in listOf(bytes.copyOf(bytes.size-1),bytes.clone().also{it[it.lastIndex]=(it.last().toInt() xor 1).toByte()})) {
            check(runCatching{ResultSnapshotCodec.read("fixture-id",ByteArrayInputStream(corrupt),key)}.isFailure)
        }
        check(runCatching{ResultSnapshotCodec.read("other-id",ByteArrayInputStream(bytes),key)}.isFailure)
    }
    val mixed=(0 until 8000).joinToString("\n"){"Field$it: demo"};val text=StringWriter()
    ResultOutputWriter.write(mixed,"vpn",ResultExport.JSON,text);check(JSONObject(text.toString()).getString("raw")==mixed)
    val deep="[".repeat(200)+"0"+"]".repeat(200);check(ResultJsonDisplay.render(deep,"vpn").isNotEmpty())
    check(runCatching{ResultJsonDisplay.render("[".repeat(201)+"0"+"]".repeat(201),"vpn")}.isFailure)
    val masked=ResultJsonDisplay.render("{\"payload\":\"{\\\"password\\\":\\\"fictional-private\\\"}\"}","vpn",true)
    check(!masked.contains("fictional-private"))
    check(runCatching{DecodedResultSnapshot.describe("invalid-\uD800")}.isFailure)
    println("Typed Kotlin: actual downloader resume, monotonic verified bytes, full JSON/text export, GCM snapshot roundtrip/tamper/AAD, iterative display: PASS")
}
