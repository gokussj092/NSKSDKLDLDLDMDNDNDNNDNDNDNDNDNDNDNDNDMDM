package com.ghostdeveloper.spdecode

import android.content.Context
import com.ghostdeveloper.spdecode.cloud.ServerVpnApp
import java.util.Locale

/** Local presentation filters only; no network requests or decoder credentials. */
internal enum class ServerVpnListFilter { ALL, ENABLED, FAVORITES }

internal object ServerVpnDirectory {
    fun visible(
        apps: List<ServerVpnApp>,
        query: String,
        filter: ServerVpnListFilter,
        favorites: Set<String>,
    ): List<ServerVpnApp> {
        val needle=query.trim()
        return apps.asSequence().filter { app ->
            val matchesSearch=needle.isEmpty() ||
                app.name.contains(needle,ignoreCase=true) ||
                app.id.contains(needle,ignoreCase=true)
            val matchesFilter=when(filter) {
                ServerVpnListFilter.ALL->true
                ServerVpnListFilter.ENABLED->app.decodeEnabled
                ServerVpnListFilter.FAVORITES->app.id in favorites
            }
            matchesSearch && matchesFilter
        }.sortedWith(compareBy<ServerVpnApp> { it.name.lowercase(Locale.ROOT) }
            .thenBy { it.id }).toList()
    }
}

/** Saved device-locally. Only the public provider catalog IDs are persisted. */
internal class ServerVpnFavorites(context: Context) {
    private val preferences=context.applicationContext.getSharedPreferences(
        "server-vpn-favorites",Context.MODE_PRIVATE)
    private val key="provider-ids"
    private val validId=Regex("[a-z0-9-]{1,48}")

    fun read():Set<String> =
        preferences.getStringSet(key,emptySet()).orEmpty()
            .filterTo(mutableSetOf()) { validId.matches(it) }

    @Synchronized fun toggle(id:String):Set<String> {
        require(validId.matches(id)) { "Invalid provider catalog ID" }
        val current=read().toMutableSet()
        if(!current.add(id))current.remove(id)
        preferences.edit().putStringSet(key,current.toSet()).apply()
        return current.toSet()
    }
}
