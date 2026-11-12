package com.ghostdeveloper.spdecode

import androidx.compose.foundation.layout.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import kotlinx.coroutines.launch
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import com.ghostdeveloper.spdecode.results.NativeResultEngine
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * Keep the worker's original bytes untouched. Some legacy HC outputs look like
 * JSON but include presentation text; only retry when the strict native JSON
 * indexer rejects that source. No decoding is retried and exports stay original.
 */
internal fun openJsonResultForViewer(raw:String,suffix:String):NativeResultEngine.Document {
    val first=raw.firstOrNull { !it.isWhitespace() }
    val startsAsJson=first=='{' || first=='['
    val source=if(startsAsJson) raw else ResultJsonDisplay.render(raw,suffix)
    return try {
        NativeResultEngine.open(source)
    }catch(error:java.io.IOException){
        if(!startsAsJson)throw error
        val normalized=ResultJsonDisplay.render(raw,suffix)
        if(normalized==source)throw error
        NativeResultEngine.open(normalized)
    }
}

/** Full indexed JSON. Search operates over native lines, not the visible window. */
@Composable
internal fun LargeResultViewer(raw: String, mask: Boolean, identity: String, suffix: String = "json") {
    key(identity, raw, suffix) {
        var failed by remember { mutableStateOf(false) }
        val document by produceState<NativeResultEngine.Document?>(null) {
            var owned: NativeResultEngine.Document? = null
            try {
                withContext(Dispatchers.Default) {
                    owned = openJsonResultForViewer(raw, suffix)
                }
                value = owned
                awaitDispose { owned?.close() }
            } catch (error: CancellationException) {
                throw error
            } catch (_: Exception) {
                failed = true
            } catch (_: LinkageError) {
                failed = true
            } finally {
                owned?.close()
            }
        }
        val current = document
        if (current == null) {
            Text(stringResource(if (failed) R.string.result_engine_error else R.string.json_viewer_loading),
                color = Color.LightGray)
        } else {
            key(mask) {
                var query by rememberSaveable { mutableStateOf("") }
                var action by remember { mutableIntStateOf(0) }
                var match by remember { mutableIntStateOf(-1) }
                var copyFailure by remember { mutableStateOf(false) }
                var copying by remember { mutableStateOf(false) }
                val taskScope=rememberCoroutineScope()
                var view by remember { mutableStateOf<ContinuousJsonView?>(null) }
                val clipboard = LocalClipboardManager.current
                val fontScale = LocalDensity.current.fontScale

                LaunchedEffect(current, mask, query, action, view) {
                    val target = view ?: return@LaunchedEffect
                    if (query.isBlank()) {
                        match = -1
                        target.highlightLine(-1)
                        return@LaunchedEffect
                    }
                    val from = if (action == 0) 0 else (match + 1).coerceAtLeast(0)
                    val next = withContext(Dispatchers.Default) {
                        val found = current.findNext(query, from, mask)
                        if (found < 0 && from > 0) current.findNext(query, 0, mask) else found
                    }
                    match = next
                    target.highlightLine(next)
                    if (next >= 0) target.scrollToLine(next)
                }

                Column(verticalArrangement = Arrangement.spacedBy(7.dp)) {
                    Row(modifier=Modifier.fillMaxWidth(),
                        horizontalArrangement=Arrangement.spacedBy(8.dp)) {
                        OutlinedTextField(
                            value=query,
                            onValueChange={query=it;action=0;match=-1},
                            label={Text(stringResource(R.string.result_search_hint))},
                            modifier=Modifier.weight(1f),
                            singleLine=true,
                            textStyle=androidx.compose.ui.text.TextStyle(color=Color.White),
                        )
                        TextButton(
                            onClick={action+=1},
                            enabled=query.isNotBlank(),
                        ) { Text(stringResource(R.string.result_search_next)) }
                    }
                    if (query.isNotBlank()) {
                        Text(
                            if (match >= 0) stringResource(R.string.result_search_line, match + 1)
                            else stringResource(R.string.result_search_empty),
                            color=Color.LightGray,fontSize=12.sp
                        )
                    }
                    AndroidView(
                        factory = { context ->
                            ContinuousJsonView(context,current,mask) { fromLine,fromColumn,toLine,toColumn ->
                                if (!copying) taskScope.launch {
                                    copying=true
                                    try {
                                        val selected=withContext(Dispatchers.Default) {
                                            current.selectedText(fromLine,fromColumn,toLine,toColumn,mask)
                                        }
                                        // The ClipboardManager uses Binder and cannot safely carry a
                                        // multi-megabyte payload. Export large reports instead.
                                        if(selected.length>700_000) copyFailure=true
                                        else clipboard.setText(AnnotatedString(selected))
                                    } catch (_:Exception) {
                                        copyFailure=true
                                    } finally {copying=false}
                                }
                            }.also { view = it }
                        },
                        modifier = Modifier.fillMaxWidth()
                            .height((current.lineCount.coerceIn(4, 150) * 22f * fontScale).dp),
                    )
                }
                if(copyFailure) {
                    Text(stringResource(R.string.result_copy_too_large),
                        color=Color(0xFFFFAAAA),fontSize=12.sp)
                }
                if(copying) CircularProgressIndicator(modifier=Modifier.size(20.dp))
            }
        }
    }
}
