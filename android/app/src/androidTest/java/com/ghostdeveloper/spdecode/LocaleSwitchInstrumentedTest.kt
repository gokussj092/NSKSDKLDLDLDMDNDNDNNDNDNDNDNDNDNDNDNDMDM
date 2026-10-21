package com.ghostdeveloper.spdecode

import android.app.Activity
import android.app.Application
import android.content.Context
import android.os.Bundle
import androidx.compose.ui.test.onAllNodesWithContentDescription
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.lifecycle.ViewModelProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.util.concurrent.atomic.AtomicReference

/** Verify a real locale-triggered Activity recreation without persisting decoded data. */
@RunWith(AndroidJUnit4::class)
class LocaleSwitchInstrumentedTest {
    @get:Rule val ui = createAndroidComposeRule<MainActivity>()

    @Test fun changingLanguagePreservesDecodedSessionInMemory() {
        val originalActivity = ui.activity
        val app = originalActivity.application
        val preferences = app.getSharedPreferences(
            "spdecode-ui-preferences", Context.MODE_PRIVATE
        )
        val before = preferences.getString("language", "system") ?: "system"
        val target = if (before == "es") "en" else "es"
        val sample = DecodeView(
            "test.xui", "xui",
            "┌─\n│SP-DECODE (.xui)\n{\n  \"Password\":\"example\"\n}\n└─", 64
        )

        // Observe Android lifecycle callbacks instead of polling ui.activity:
        // the Compose test host can still be switching roots during recreate().
        val recreatedActivity = AtomicReference<MainActivity?>(null)
        val callbacks = object : Application.ActivityLifecycleCallbacks {
            override fun onActivityResumed(activity: Activity) {
                if (activity is MainActivity && activity !== originalActivity) {
                    recreatedActivity.set(activity)
                }
            }
            override fun onActivityCreated(activity: Activity, state: Bundle?) = Unit
            override fun onActivityStarted(activity: Activity) = Unit
            override fun onActivityPaused(activity: Activity) = Unit
            override fun onActivityStopped(activity: Activity) = Unit
            override fun onActivitySaveInstanceState(activity: Activity, state: Bundle) = Unit
            override fun onActivityDestroyed(activity: Activity) = Unit
        }
        app.registerActivityLifecycleCallbacks(callbacks)
        try {
            ui.waitUntil(10_000) {
                ui.onAllNodesWithContentDescription(
                    originalActivity.getString(R.string.settings)
                ).fetchSemanticsNodes().isNotEmpty()
            }
            if (ui.onAllNodesWithText(
                    originalActivity.getString(R.string.whats_new_continue)
                ).fetchSemanticsNodes().isNotEmpty()
            ) {
                ui.onNodeWithText(
                    originalActivity.getString(R.string.whats_new_continue)
                ).performClick()
            }

            ui.runOnUiThread {
                val vm = ViewModelProvider(originalActivity)[DecodeSessionViewModel::class.java]
                vm.current = sample
                vm.recent.add(0, sample)
            }
            // Navigate through the actual Settings tab rather than changing
            // ViewModel.tab directly and racing Compose recomposition.
            ui.onNodeWithContentDescription(
                originalActivity.getString(R.string.settings)
            ).performClick()
            ui.onNodeWithText(
                originalActivity.getString(R.string.language_title)
            ).performClick()
            ui.onNodeWithTag("settings_language_screen").assertExists()
            ui.onNodeWithTag("language_option_${target}").performClick()

            // A preference write is not proof that an Activity was recreated.
            ui.waitUntil(20_000) { recreatedActivity.get() != null }
            ui.runOnIdle {
                val activeActivity = requireNotNull(recreatedActivity.get()) {
                    "No new MainActivity reached RESUMED after choosing $target"
                }
                assertNotSame("Changing language must recreate MainActivity",
                    originalActivity, activeActivity)
                assertEquals("Selected locale must be persisted", target,
                    preferences.getString("language", null))
                assertEquals("New Activity must use the selected locale", target,
                    activeActivity.resources.configuration.locales[0].language)

                val vm = ViewModelProvider(activeActivity)[DecodeSessionViewModel::class.java]
                assertEquals("Decoded result must survive recreation",
                    sample.rawText, vm.current?.rawText)
                assertEquals("Decoded session entry must not be duplicated",
                    1, vm.recent.count { it.rawText == sample.rawText })
            }
        } finally {
            app.unregisterActivityLifecycleCallbacks(callbacks)
            // Restore the test-only preference even when an assertion fails.
            assertTrue("Failed to restore locale preference",
                preferences.edit().putString("language", before).commit())
        }
    }
}
