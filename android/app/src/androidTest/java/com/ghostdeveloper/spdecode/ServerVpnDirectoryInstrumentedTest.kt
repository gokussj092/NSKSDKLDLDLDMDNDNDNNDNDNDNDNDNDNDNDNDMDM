package com.ghostdeveloper.spdecode

import android.graphics.Bitmap
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import com.ghostdeveloper.spdecode.cloud.ServerVpnApp
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class ServerVpnDirectoryInstrumentedTest {
    private fun app(id:String,name:String,enabled:Boolean)=ServerVpnApp(
        id,name,Bitmap.createBitmap(1,1,Bitmap.Config.ARGB_8888),enabled)

    @Test fun queryAndAvailabilityFiltersAreLocalAndSorted() {
        val apps=listOf(
            app("zebra-vpn","Zebra VPN",true),
            app("alpha-vpn","Alpha VPN",false),
            app("beta-vpn","Beta VPN",true),
        )
        val all=ServerVpnDirectory.visible(apps,"",ServerVpnListFilter.ALL,emptySet())
        assertEquals(listOf("alpha-vpn","beta-vpn","zebra-vpn"),all.map { it.id })
        val available=ServerVpnDirectory.visible(
            apps,"",ServerVpnListFilter.ENABLED,emptySet())
        assertEquals(listOf("beta-vpn","zebra-vpn"),available.map { it.id })
        val search=ServerVpnDirectory.visible(
            apps,"  BETA  ",ServerVpnListFilter.ALL,emptySet())
        assertEquals(listOf("beta-vpn"),search.map { it.id })
        // The stable provider ID can be searched independently of the display name.
        assertEquals(listOf("zebra-vpn"),ServerVpnDirectory.visible(
            apps,"zebra-vpn",ServerVpnListFilter.ALL,emptySet()).map { it.id })
    }

    @Test fun favoritesFilterOnlyIncludesSavedIds() {
        val apps=listOf(app("a-vpn","Alpha",true),app("b-vpn","Beta",false))
        assertEquals(listOf("b-vpn"),ServerVpnDirectory.visible(
            apps,"",ServerVpnListFilter.FAVORITES,setOf("b-vpn")).map { it.id })
        assertTrue(ServerVpnDirectory.visible(
            apps,"Alpha",ServerVpnListFilter.FAVORITES,setOf("b-vpn")).isEmpty())
    }

    @Test fun favoritesSurviveRecreatingStoreWithoutNetwork() {
        val context=InstrumentationRegistry.getInstrumentation().targetContext
        val id="test-server-vpn-favorite-2026"
        val first=ServerVpnFavorites(context)
        if(id in first.read()) first.toggle(id)
        try {
            assertTrue(id in first.toggle(id))
            assertTrue(id in ServerVpnFavorites(context).read())
            assertFalse(id in ServerVpnFavorites(context).toggle(id))
            assertFalse(id in ServerVpnFavorites(context).read())
        }finally {
            if(id in first.read())first.toggle(id)
        }
    }

    @Test fun favoritesRejectInvalidProviderIds() {
        val context=InstrumentationRegistry.getInstrumentation().targetContext
        assertThrows(IllegalArgumentException::class.java) {
            ServerVpnFavorites(context).toggle("../secret")
        }
    }
}
