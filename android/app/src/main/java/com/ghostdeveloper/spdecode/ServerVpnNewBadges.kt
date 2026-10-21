package com.ghostdeveloper.spdecode

import android.content.Context

/**
 * Two-hour, device-clock badges for newly published VPN catalog entries and
 * newly introduced UI actions. Never reads server time or sends identifiers.
 */
internal class ServerVpnNewBadges(
    context:Context,
    preferenceName:String="server-vpn-new-badges",
) {
    companion object {
        const val DURATION_MS=2L*60L*60L*1000L
        const val MANUAL_REFRESH_FEATURE="server-vpn-manual-refresh-v1"
        private const val KNOWN_IDS="known-provider-ids"
        private const val PREFIX="provider:"
        private const val FEATURE_PREFIX="feature:"
        private val VALID_ID=Regex("[a-z0-9-]{1,48}")
    }

    internal data class Snapshot(val ids:Set<String>, val nextExpiryMs:Long?)
    private val preferences=context.applicationContext.getSharedPreferences(
        preferenceName,Context.MODE_PRIVATE)

    /** A valid initial catalog forms the baseline. Existing entries are not
     * falsely labeled as new on a fresh app install or migrated preferences. */
    @Synchronized
    fun observeCatalog(
        ids:Set<String>,
        nowMillis:Long=System.currentTimeMillis(),
    ):Snapshot {
        val valid=ids.filterTo(mutableSetOf()) { VALID_ID.matches(it) }
        val existing=preferences.getStringSet(KNOWN_IDS,null)?.toSet()
        if(existing==null) {
            if(valid.isNotEmpty()) {
                preferences.edit().putStringSet(KNOWN_IDS,valid.toSet()).apply()
            }
            return Snapshot(emptySet(),null)
        }
        val added=valid-existing
        if(added.isNotEmpty()) {
            val edit=preferences.edit().putStringSet(
                KNOWN_IDS,(existing+valid).toSet())
            for(id in added) edit.putLong(PREFIX+id,nowMillis)
            edit.apply()
        }
        val active=mutableSetOf<String>()
        var nextExpiry:Long?=null
        val remove=preferences.edit()
        var hasRemovals=false
        for((key,value) in preferences.all) {
            if(!key.startsWith(PREFIX))continue
            val born=value as? Long
            val remaining=if(born==null) null else remaining(born,nowMillis)
            if(remaining==null) {
                remove.remove(key)
                hasRemovals=true
            }else if(key.removePrefix(PREFIX) in valid) {
                active+=key.removePrefix(PREFIX)
                nextExpiry=if(nextExpiry==null)remaining else minOf(nextExpiry,remaining)
            }
        }
        if(hasRemovals)remove.apply()
        return Snapshot(active,nextExpiry)
    }

    /** Returns milliseconds left before the feature tag must disappear.
     * Once expired the original timestamp remains, preventing resurrection. */
    @Synchronized
    fun featureRemaining(
        featureId:String,
        nowMillis:Long=System.currentTimeMillis(),
    ):Long? {
        require(VALID_ID.matches(featureId))
        val key=FEATURE_PREFIX+featureId
        val born=if(preferences.contains(key))preferences.getLong(key,0L)
            else nowMillis.also { preferences.edit().putLong(key,it).apply() }
        if(born==Long.MIN_VALUE)return null
        val left=remaining(born,nowMillis)
        if(left==null) {
            // Tombstone an expired or clock-rolled-back feature so setting the
            // clock back cannot make a previously expired label appear again.
            preferences.edit().putLong(key,Long.MIN_VALUE).apply()
        }
        return left
    }

    private fun remaining(born:Long,now:Long):Long? {
        val elapsed=now-born
        // Clock rollback should never extend a badge or resurrect an expired one.
        return if(elapsed<0L || elapsed>=DURATION_MS) null else DURATION_MS-elapsed
    }
}
