package com.ghostdeveloper.spdecode

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ghostdeveloper.spdecode.results.NativeResultEngine
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject

/** Native index + bounded JNI pages; never constructs a Gson DOM or pretty copy. */
@Composable
internal fun LargeResultViewer(raw:String,mask:Boolean,identity:String) {
    var failed by remember(identity,raw){mutableStateOf(false)}
    val document by produceState<NativeResultEngine.Document?>(null,identity,raw) {
        var owned:NativeResultEngine.Document?=null
        try {
            withContext(Dispatchers.Default){owned=NativeResultEngine.open(raw)}
            value=owned
            awaitDispose { owned?.close() }
        }catch(e:CancellationException){throw e}
         catch(_:Exception){failed=true}
         catch(_:LinkageError){failed=true}
         finally{owned?.close()}
    }
    val doc=document
    if(doc==null){Text(stringResource(if(failed)R.string.result_engine_error else R.string.json_viewer_loading),color=Color.LightGray);return}
    // Discard every rendered row/value dialog immediately on privacy changes.
    key(identity,mask){NativeResultPage(doc,mask)}
}

@Composable
private fun NativeResultPage(document:NativeResultEngine.Document,mask:Boolean) {
    var parent by remember{mutableIntStateOf(0)}
    var offset by remember{mutableIntStateOf(0)}
    val back=remember{mutableStateListOf<Pair<Int,Int>>()}
    val pageBack=remember{mutableStateMapOf<Int,List<Int>>()}
    var selected by remember{mutableStateOf<Int?>(null)}
    var pageFailed by remember(document,parent,offset,mask){mutableStateOf(false)}
    val page by produceState<JSONObject?>(null,document,parent,offset,mask) {
        value=null
        value=withContext(Dispatchers.Default){runCatching{document.page(parent,offset,mask)}.getOrNull()}
        pageFailed=value==null
    }
    Column(Modifier.fillMaxWidth()) {
        if(back.isNotEmpty())TextButton(onClick={val previous=back.removeAt(back.lastIndex);parent=previous.first;offset=previous.second}){Text(stringResource(R.string.result_previous_page))}
        val current=page
        if(current==null){Text(stringResource(if(pageFailed)R.string.result_engine_error else R.string.json_viewer_loading),color=Color.LightGray);return@Column}
        val array=current.getJSONArray("rows")
        val rows=List(array.length()){array.getJSONObject(it)}
        LazyColumn(Modifier.fillMaxWidth().heightIn(min=100.dp,max=480.dp)) {
            items(rows,key={it.getInt("id")}) { row ->
                val type=row.getString("type")
                val container=type=="object"||type=="array"
                val hidden=row.getBoolean("hidden")
                val key=row.getString("key");val value=if(hidden)"••••••••" else if(container)"${if(type=="array")"[…]" else "{…}"} (${row.getInt("count")})" else row.getJSONObject("slice").getString("value")
                Text((if(row.getBoolean("hasKey"))JSONObject.quote(key)+": " else "")+(if(type=="text")JSONObject.quote(value) else value),
                    modifier=Modifier.fillMaxWidth().clickable(enabled=!hidden) {
                        if(container){back.add(parent to offset);parent=row.getInt("id");pageBack[parent]=emptyList();offset=0}else selected=row.getInt("id")
                    }.padding(vertical=6.dp),color=if(container)Color(0xFF7CB7F9) else Color(0xFF98D9A0),fontSize=13.sp,
                    style=TextStyle(textDirection=TextDirection.Ltr))
            }
        }
        Row(Modifier.fillMaxWidth(),horizontalArrangement=Arrangement.SpaceBetween) {
            if(offset>0)TextButton(onClick={val previous=pageBack[parent].orEmpty();offset=previous.lastOrNull()?:0;pageBack[parent]=previous.dropLast(1)}){Text(stringResource(R.string.result_previous_page))}
            if(current.getBoolean("hasMore"))TextButton(onClick={pageBack[parent]=pageBack[parent].orEmpty()+offset;offset=current.getInt("next")}){Text(stringResource(R.string.json_more_items,64))}
        }
    }
    selected?.let { id -> NativeValueDialog(document,id,mask){selected=null} }
}

@Composable
private fun NativeValueDialog(document:NativeResultEngine.Document,node:Int,mask:Boolean,onDismiss:()->Unit) {
    var offset by remember(node,mask){mutableIntStateOf(0)}
    val previous=remember(node,mask){mutableStateListOf<Int>()}
    val slice by produceState<JSONObject?>(null,document,node,offset,mask){value=withContext(Dispatchers.Default){runCatching{document.value(node,offset,mask)}.getOrNull()}}
    AlertDialog(onDismissRequest=onDismiss,containerColor=Color.Black,
        text={Text(slice?.optString("value").orEmpty(),color=Color.White,fontSize=13.sp)},
        confirmButton={TextButton(onClick=onDismiss){Text(stringResource(R.string.catalog_transfer_finish))}},
        dismissButton={Row {
            if(previous.isNotEmpty())TextButton(onClick={offset=previous.removeAt(previous.lastIndex)}){Text(stringResource(R.string.result_previous_page))}
            val value=slice
            if(value!=null&&value.getInt("next")<value.getInt("totalBytes"))TextButton(onClick={previous.add(offset);offset=value.getInt("next")}){Text(stringResource(R.string.json_more_chars,4096))}
        }})
}
