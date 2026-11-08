package com.ghostdeveloper.spdecode

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.viewinterop.AndroidView
import com.ghostdeveloper.spdecode.results.NativeResultEngine
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** Full indexed JSON. Search operates over native lines, not the visible window. */
@Composable
internal fun LargeResultViewer(raw: String, mask: Boolean, identity: String, suffix: String = "json") {
    key(identity, raw, suffix) {
        var failed by remember { mutableStateOf(false) }
        val document by produceState<NativeResultEngine.Document?>(null) {
            var owned: NativeResultEngine.Document? = null
            try {
                withContext(Dispatchers.Default) {
                    val first = raw.firstOrNull { !it.isWhitespace() }
                    val source = if (first == '{' || first == '[') raw
                        else ResultJsonDisplay.render(raw, suffix)
                    owned = NativeResultEngine.open(source)
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
                var snippet by remember { mutableStateOf<String?>(null) }
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
                            ContinuousJsonView(context, current, mask) { line, column ->
                                snippet = runCatching {
                                    current.lineWindow(line, column, 2048, mask)
                                        .optString("text", "")
                                }.getOrNull()
                            }.also { view = it }
                        },
                        modifier = Modifier.fillMaxWidth()
                            .height((current.lineCount.coerceIn(4, 150) * 22f * fontScale).dp),
                    )
                }
                if (snippet != null) {
                    val text = requireNotNull(snippet)
                    AlertDialog(
                        onDismissRequest={snippet=null},
                        title={Text(stringResource(R.string.result_select_fragment))},
                        text={
                            Column(Modifier.heightIn(max=320.dp)
                                .verticalScroll(rememberScrollState())) {
                                SelectionContainer {
                                    Text(text,color=Color.White,fontSize=12.sp,
                                        fontFamily=FontFamily.Monospace)
                                }
                            }
                        },
                        confirmButton={
                            TextButton(onClick={clipboard.setText(AnnotatedString(text));snippet=null}) {
                                Text(stringResource(R.string.result_copy_fragment))
                            }
                        },
                        dismissButton={
                            TextButton(onClick={snippet=null}) {
                                Text(stringResource(R.string.cancel))
                            }
                        },
                    )
                }
            }
        }
    }
}
