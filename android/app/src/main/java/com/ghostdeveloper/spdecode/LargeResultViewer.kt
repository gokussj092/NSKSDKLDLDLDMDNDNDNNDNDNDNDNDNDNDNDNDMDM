package com.ghostdeveloper.spdecode

import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import com.ghostdeveloper.spdecode.results.NativeResultEngine
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/** All logical lines are indexed; only the visible text is drawn or crosses JNI. */
@Composable
internal fun LargeResultViewer(raw: String, mask: Boolean, identity: String, suffix: String = "json") {
    key(identity, raw, suffix) {
        var failed by remember { mutableStateOf(false) }
        val document by produceState<NativeResultEngine.Document?>(null) {
            var owned: NativeResultEngine.Document? = null
            try {
                withContext(Dispatchers.Default) {
                    val first = raw.firstOrNull { !it.isWhitespace() }
                    // Keep JSON bytes intact, including duplicate keys and long values.
                    // Legacy decoder text still uses the existing JSON conversion.
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
            // Destroy all visible unmasked strings immediately when privacy changes.
            key(mask) {
                AndroidView(
                    factory = { context -> ContinuousJsonView(context, current, mask) },
                    modifier = Modifier.fillMaxWidth().height(440.dp),
                )
            }
        }
    }
}
