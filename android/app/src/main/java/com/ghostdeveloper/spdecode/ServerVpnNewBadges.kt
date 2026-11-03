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
        private const val METHOD_VERSION_PREFIX="method-version:"
        private const val METHOD_PREFIX="method-updated:"
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
            val left=if(born==null) null else remaining(born,nowMillis)
            if(left==null) {
                remove.remove(key)
                hasRemovals=true
            }else if(key.removePrefix(PREFIX) in valid) {
                active+=key.removePrefix(PREFIX)
                val previous=nextExpiry
                nextExpiry=if(previous==null)left else minOf(previous,left)
            }
        }
        if(hasRemovals)remove.apply()
        return Snapshot(active,nextExpiry)
    }

    /** Explicit method revisions are device-local and independent of icon,
     * provider availability and overall catalog version. The first verified
     * catalog establishes a baseline; later higher revisions get a 2h marker. */
    @Synchronized
    fun observeMethods(
        revisions:Map<String,Int>,
        nowMillis:Long=System.currentTimeMillis(),
    ):Snapshot {
        val valid=revisions.filter { (id,version) ->
            VALID_ID.matches(id) && version in 0..1_000_000
        }
        val edit=preferences.edit()
        var changed=false
        for((id,revision) in valid) {
            val key=METHOD_VERSION_PREFIX+id
            if(!preferences.contains(key)) {
                edit.putInt(key,revision)
                changed=true
            }else{
                val old=preferences.getInt(key,0)
                if(revision>old) {
                    edit.putInt(key,revision)
                    edit.putLong(METHOD_PREFIX+id,nowMillis)
                    changed=true
                }
            }
        }
        if(changed)edit.apply()
        val active=mutableSetOf<String>()
        var nextExpiry:Long?=null
        val cleanup=preferences.edit()
        var expired=false
        for((id,_) in valid) {
            val key=METHOD_PREFIX+id
            if(!preferences.contains(key))continue
            val remaining=remaining(preferences.getLong(key,0L),nowMillis)
            if(remaining==null) {
                cleanup.remove(key)
                expired=true
            }else{
                active+=id
                nextExpiry=nextExpiry?.let { minOf(it,remaining) } ?: remaining
            }
        }
        if(expired)cleanup.apply()
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
