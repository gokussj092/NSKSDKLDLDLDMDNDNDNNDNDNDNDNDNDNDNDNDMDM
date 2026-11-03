package com.ghostdeveloper.spdecode

import android.content.Context
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.util.UUID

@RunWith(AndroidJUnit4::class)
class ServerVpnNewBadgesInstrumentedTest {
    private val context get()=InstrumentationRegistry.getInstrumentation().targetContext
    private val start=1_800_000_000_000L

    private fun withStore(block:(ServerVpnNewBadges)->Unit) {
        val name="new-badge-test-"+UUID.randomUUID().toString()
        val preferences=context.getSharedPreferences(name,Context.MODE_PRIVATE)
        preferences.edit().clear().commit()
        try{block(ServerVpnNewBadges(context,name))}
        finally{preferences.edit().clear().commit()}
    }

    @Test fun initialCatalogIsBaselineButLaterProvidersGetBadge()=withStore { tracker ->
        assertTrue(tracker.observeCatalog(emptySet(),start).ids.isEmpty())
        assertTrue(tracker.observeCatalog(setOf("known-vpn"),start).ids.isEmpty())
        val first=tracker.observeCatalog(setOf("known-vpn","added-vpn"),start+60_000)
        assertEquals(setOf("added-vpn"),first.ids)
        assertEquals(ServerVpnNewBadges.DURATION_MS,first.nextExpiryMs)
        assertEquals(setOf("added-vpn"),tracker.observeCatalog(
            setOf("known-vpn","added-vpn"),start+60_000).ids)
    }

    @Test fun badgesExpireAtTwoHoursAndNeverReturn()=withStore { tracker ->
        tracker.observeCatalog(setOf("base-vpn"),start)
        tracker.observeCatalog(setOf("base-vpn","new-vpn"),start+3L)
        assertEquals(setOf("new-vpn"),tracker.observeCatalog(
            setOf("base-vpn","new-vpn"),
            start+3L+ServerVpnNewBadges.DURATION_MS-1L).ids)
        assertTrue(tracker.observeCatalog(
            setOf("base-vpn","new-vpn"),
            start+3L+ServerVpnNewBadges.DURATION_MS).ids.isEmpty())
        assertTrue(tracker.observeCatalog(
            setOf("base-vpn","new-vpn"),start+3L).ids.isEmpty())
        assertTrue(tracker.observeCatalog(
            setOf("base-vpn","new-vpn"),start+100_000_000L).ids.isEmpty())
    }

    @Test fun newFeatureUsesDeviceTimeAndExpiresPermanently()=withStore { tracker ->
        val id=ServerVpnNewBadges.MANUAL_REFRESH_FEATURE
        assertEquals(ServerVpnNewBadges.DURATION_MS,
            tracker.featureRemaining(id,start))
        assertEquals(1L,tracker.featureRemaining(
            id,start+ServerVpnNewBadges.DURATION_MS-1L))
        assertNull(tracker.featureRemaining(
            id,start+ServerVpnNewBadges.DURATION_MS))
        assertNull(tracker.featureRemaining(id,start))
    }

    @Test fun catalogReorderingAndDisablingDoNotRearmBadges()=withStore { tracker ->
        tracker.observeCatalog(setOf("provider-a","provider-b"),start)
        assertTrue(tracker.observeCatalog(
            setOf("provider-b","provider-a"),start+5).ids.isEmpty())
        assertTrue(tracker.observeCatalog(
            setOf("provider-a"),start+50).ids.isEmpty())
        assertTrue(tracker.observeCatalog(
            setOf("provider-a","provider-b"),start+60).ids.isEmpty())
    }

    @Test fun methodRevisionsOnlyMarkExplicitChangesAndDoNotReappear()=withStore { tracker ->
        assertTrue(tracker.observeMethods(mapOf("provider-a" to 3),start).ids.isEmpty())
        val updated=tracker.observeMethods(mapOf("provider-a" to 4),start+100)
        assertEquals(setOf("provider-a"),updated.ids)
        assertTrue(tracker.observeMethods(mapOf("provider-a" to 4),
            start+100+ServerVpnNewBadges.DURATION_MS).ids.isEmpty())
        assertTrue(tracker.observeMethods(mapOf("provider-a" to 4),start+100).ids.isEmpty())
        assertEquals(setOf("provider-a"),tracker.observeMethods(
            mapOf("provider-a" to 5),start+200).ids)
    }

    @Test fun methodStatusesHaveDeterministicPriority(){
        assertEquals(ServerVpnBadgeType.MAINTENANCE,
            ServerVpnBadgePriority.resolve(true,true,true))
        assertEquals(ServerVpnBadgeType.UPDATED,
            ServerVpnBadgePriority.resolve(false,true,true))
        assertEquals(ServerVpnBadgeType.NEW,
            ServerVpnBadgePriority.resolve(false,false,true))
        assertNull(ServerVpnBadgePriority.resolve(false,false,false))
    }

}