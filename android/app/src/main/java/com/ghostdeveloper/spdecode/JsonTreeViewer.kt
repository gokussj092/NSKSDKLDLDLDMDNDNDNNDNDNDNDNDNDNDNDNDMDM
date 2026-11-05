package com.ghostdeveloper.spdecode

import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.ChevronRight
import androidx.compose.material.icons.outlined.ExpandMore
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.style.TextDirection
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.google.gson.JsonElement
import com.google.gson.JsonPrimitive
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

// Syntax colors apply ONLY to JSON tokens. No app theme, surfaces, buttons,
// header, settings, copy/export actions or navigation colors are modified.
private val JsonKey = Color(0xFF7CB7F9)
private val JsonString = Color(0xFF98D9A0)
private val JsonNumber = Color(0xFFE8B66D)
private val JsonBoolean = Color(0xFFC9A0F3)
private val JsonNull = Color(0xFFE7A5B4)
private val JsonPunctuation = Color(0xFFF7F7F7)
private val JsonSecondary = Color(0xFFABABAB)

/**
 * Bounded lazy viewport with parsing off the UI thread. Large documents use
 * native pages; small nested branches start collapsed. The raw source is immutable.
 */
@Composable
internal fun JsonTreeViewer(
    raw: String,
    suffix: String,
    maskCredentials: Boolean,
    identity: String,
) {
    val extensive=remember(identity,raw){raw.length>=64*1024 || raw.count{it=='\n'||it=='\r'}>1000}
    if(extensive) {
        key(identity,raw){LargeResultViewer(raw,maskCredentials,identity)}
        return
    }
    // Keyed content prevents a frame of *unmasked* JSON from surviving
    // when the user switches the sensitive-values toggle.
    key(identity, maskCredentials, raw, suffix) {
        JsonTreeViewerContent(raw, suffix, maskCredentials, identity)
    }
}

@Composable
private fun JsonTreeViewerContent(
    raw: String,
    suffix: String,
    maskCredentials: Boolean,
    identity: String,
) {
    var failed by remember(identity,raw,maskCredentials){mutableStateOf(false)}
    val document by produceState<JsonElement?>(
        initialValue = null, raw, suffix, maskCredentials, identity
    ) {
        value = withContext(Dispatchers.Default) {
            try {ResultJsonDisplay.element(raw, suffix, maskCredentials)}
            catch(error:kotlinx.coroutines.CancellationException){throw error}
            catch(_:Exception){failed=true;null}
        }
    }

    val expanded = remember(identity, maskCredentials) { mutableStateMapOf<String, Boolean>() }
    val root = document

    if (root == null) {
        Text(stringResource(if(failed)R.string.result_engine_error else R.string.json_viewer_loading),
            color = JsonSecondary, fontSize = 13.sp,
            style = TextStyle(textDirection = TextDirection.Ltr))
        return
    }

    val rows by remember(root, identity, maskCredentials) {
        derivedStateOf { JsonTreeProjection.project(root, expanded) }
    }
    LazyColumn(modifier = Modifier.fillMaxWidth().heightIn(min=100.dp,max=480.dp).padding(vertical = 2.dp)) {
        items(rows,key={"${it.path}:${it.kind}"}) { row ->
            key("${row.path}:${row.kind}") {
                val indent = (row.depth.coerceAtMost(32) * 12).dp
                when (row.kind) {
                    JsonTreeProjection.Kind.NODE -> {
                        Row(
                            modifier = Modifier.fillMaxWidth().clickable {
                                expanded[row.path] = !row.expanded
                            }.padding(start = indent, top = 2.dp, bottom = 2.dp),
                            verticalAlignment = Alignment.CenterVertically,
                        ) {
                            androidx.compose.material3.Icon(
                                if (row.expanded) Icons.Outlined.ExpandMore
                                else Icons.Outlined.ChevronRight,
                                contentDescription = stringResource(
                                    if (row.expanded) R.string.json_collapse else R.string.json_expand),
                                tint = JsonSecondary,
                                modifier = Modifier.size(16.dp)
                            )
                            Text(
                                jsonLine(row),
                                modifier = Modifier.weight(1f),
                                fontSize = 13.sp, lineHeight = 19.sp,
                                style = TextStyle(textDirection = TextDirection.Ltr)
                            )
                        }
                    }
                    JsonTreeProjection.Kind.VALUE -> {
                        SelectionContainer {
                            Text(jsonLine(row), modifier = Modifier.fillMaxWidth()
                                .padding(start = indent + 16.dp, top = 2.dp, bottom = 2.dp),
                                fontSize = 13.sp, lineHeight = 19.sp,
                                style = TextStyle(textDirection = TextDirection.Ltr))
                        }
                    }
                    JsonTreeProjection.Kind.END -> {
                        Text(jsonLine(row), modifier = Modifier.fillMaxWidth()
                            .padding(start = indent + 16.dp, top = 2.dp, bottom = 2.dp),
                            fontSize = 13.sp, lineHeight = 19.sp,
                            style = TextStyle(textDirection = TextDirection.Ltr))
                    }
                }
            }
        }
    }
}

/** AnnotatedString gives semantic token colors without changing the Android theme. */
private fun jsonLine(row: JsonTreeProjection.Row) =
    buildAnnotatedString {
        row.key?.let { name ->
            withStyle(SpanStyle(color = JsonKey)) {
                append(JsonPrimitive(name).toString())
            }
            withStyle(SpanStyle(color = JsonPunctuation)) { append(": ") }
        }
        when (row.kind) {
            JsonTreeProjection.Kind.NODE -> {
                withStyle(SpanStyle(color = JsonPunctuation)) {
                    append(row.bracket)
                    if (!row.expanded) {
                        append(" … ")
                        append(if (row.bracket == '{') '}' else ']')
                    }
                    if (!row.expanded && row.comma) append(',')
                }
                if (!row.expanded) withStyle(SpanStyle(color = JsonSecondary)) {
                    append("  // ")
                    append(row.total.toString())
                }
            }
            JsonTreeProjection.Kind.END -> {
                withStyle(SpanStyle(color = JsonPunctuation)) {
                    append(row.bracket)
                    if (row.comma) append(',')
                }
            }
            JsonTreeProjection.Kind.VALUE -> {
                val value = row.value
                when {
                    value == null || value.isJsonNull ->
                        withStyle(SpanStyle(color = JsonNull)) { append("null") }
                    value.isJsonPrimitive && value.asJsonPrimitive.isString -> {
                        withStyle(SpanStyle(color = JsonString)) {
                            append(JsonPrimitive(value.asString).toString())
                        }
                    }
                    value.isJsonPrimitive && value.asJsonPrimitive.isBoolean ->
                        withStyle(SpanStyle(color = JsonBoolean)) { append(value.toString()) }
                    else -> withStyle(SpanStyle(color = JsonNumber)) { append(value.toString()) }
                }
                if (row.comma) withStyle(SpanStyle(color = JsonPunctuation)) { append(',') }
            }
        }
    }
