package com.ghostdeveloper.spdecode

/** Server-supplied status takes precedence; client badges never guess the cause. */
internal enum class ServerVpnBadgeType { NEW, UPDATED, MAINTENANCE }
internal object ServerVpnBadgePriority {
    fun resolve(maintenance:Boolean,updated:Boolean,newlyAdded:Boolean):ServerVpnBadgeType? =
        when {
            maintenance -> ServerVpnBadgeType.MAINTENANCE
            updated -> ServerVpnBadgeType.UPDATED
            newlyAdded -> ServerVpnBadgeType.NEW
            else -> null
        }
}
