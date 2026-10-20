package com.ghostdeveloper.spdecode

import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Exercise actual Android 15/16 system insets with a launched Cloud Activity. */
@RunWith(AndroidJUnit4::class)
class PlayEdgeToEdgeInstrumentedTest {
    @get:Rule val rule=createAndroidComposeRule<MainActivity>()

    @Test fun headerAndBottomTabsRespectSystemInsets() {
        val home=rule.activity.getString(R.string.home)
        rule.waitUntil(timeoutMillis=30_000) {
            rule.onAllNodesWithText(home,useUnmergedTree=true)
                .fetchSemanticsNodes().isNotEmpty()
        }
        rule.waitForIdle()
        val decor=rule.activity.window.decorView
        val insets=ViewCompat.getRootWindowInsets(decor)
        assertNotNull("System insets unavailable",insets)
        val top=insets!!.getInsets(WindowInsetsCompat.Type.statusBars()).top
        val bottom=insets.getInsets(WindowInsetsCompat.Type.navigationBars()).bottom
        val titleBounds=rule.onNodeWithText("SP-DECODE",useUnmergedTree=true)
            .fetchSemanticsNode().boundsInWindow
        val tabBounds=rule.onNodeWithText(home,useUnmergedTree=true)
            .fetchSemanticsNode().boundsInWindow
        assertTrue("Header hidden by status bar: $titleBounds top inset $top",
            titleBounds.top >= top-2f)
        assertTrue("Bottom tab hidden by navigation bar: $tabBounds bottom inset $bottom",
            tabBounds.bottom <= decor.height-bottom+2f)
    }
}
