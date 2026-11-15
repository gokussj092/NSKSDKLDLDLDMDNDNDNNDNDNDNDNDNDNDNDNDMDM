package com.ghostdeveloper.spdecode

import com.google.gson.JsonElement

/** Read-only small-document rows. Nested branches are collapsed by default.
 * Paths use sibling indices so unusual field names cannot collide.
 * Iterative traversal preserves deeply nested data without recursive projection.
 */
internal object JsonTreeProjection {
    enum class Kind { NODE, VALUE, END }

    data class Row(
        val path: String,
        val depth: Int,
        val kind: Kind,
        val key: String? = null,
        val value: JsonElement? = null,
        val bracket: Char = ' ',
        val expanded: Boolean = false,
        val total: Int = 0,
        val comma: Boolean = false,
    )

    private data class Pending(
        val element: JsonElement?, val key: String?, val path: String,
        val depth: Int, val comma: Boolean, val closing: Char = ' ',
    )

    fun project(
        root: JsonElement,
        expandedOverrides: Map<String, Boolean> = emptyMap(),
    ): List<Row> {
        val result = ArrayList<Row>()
        val pending = ArrayDeque<Pending>()
        pending.addLast(Pending(root, null, "root", 0, false))
        while (pending.isNotEmpty()) {
            val item = pending.removeLast()
            val element = item.element
            if (element == null) {
                result.add(Row(item.path, item.depth, Kind.END,
                    bracket = item.closing, comma = item.comma))
                continue
            }
            if (!element.isJsonObject && !element.isJsonArray) {
                result.add(Row(item.path, item.depth, Kind.VALUE, item.key,
                    element, comma = item.comma))
                continue
            }
            val obj = if (element.isJsonObject) element.asJsonObject else null
            val arr = if (element.isJsonArray) element.asJsonArray else null
            val total = obj?.size() ?: arr!!.size()
            val isExpanded = expandedOverrides[item.path] ?: (item.path=="root")
            result.add(Row(item.path, item.depth, Kind.NODE, item.key,
                bracket = if (obj != null) '{' else '[', expanded = isExpanded,
                total = total, comma = item.comma))
            if (!isExpanded) continue
            pending.addLast(Pending(null, null, "${item.path}/end", item.depth,
                item.comma, if (obj != null) '}' else ']'))
            if (obj != null) {
                val entries = obj.entrySet().toList()
                for (index in entries.indices.reversed()) {
                    val entry = entries[index]
                    pending.addLast(Pending(entry.value, entry.key,
                        "${item.path}/$index", item.depth + 1, index < total - 1))
                }
            } else {
                for (index in (0 until total).reversed()) {
                    pending.addLast(Pending(arr!![index], null, "${item.path}/$index",
                        item.depth + 1, index < total - 1))
                }
            }
        }
        return result
    }
}
