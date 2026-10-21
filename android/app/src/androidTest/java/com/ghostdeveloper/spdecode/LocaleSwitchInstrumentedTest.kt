package com.ghostdeveloper.spdecode

import android.content.Context
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onAllNodesWithContentDescription
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.lifecycle.ViewModelProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** Actual Activity locale recreation and no decoded session disk persistence. */
@RunWith(AndroidJUnit4::class)
class LocaleSwitchInstrumentedTest {
    @get:Rule val ui=createAndroidComposeRule<MainActivity>()

    @Test fun changingLanguagePreservesDecodedSessionInMemory() {
        val ctx=ui.activity
        ui.waitUntil(10000) {
            ui.onAllNodesWithContentDescription(ctx.getString(R.string.settings))
                .fetchSemanticsNodes().isNotEmpty()
        }
        if(ui.onAllNodesWithText(ctx.getString(R.string.whats_new_continue)).fetchSemanticsNodes().isNotEmpty())
            ui.onNodeWithText(ctx.getString(R.string.whats_new_continue)).performClick()
        val before=ctx.getSharedPreferences("spdecode-ui-preferences",Context.MODE_PRIVATE)
            .getString("language","system")?:"system"
        val sample=DecodeView("test.xui","xui",
            "┌─\n│SP-DECODE (.xui)\n{\n  \"Password\":\"example\"\n}\n└─",64)
        try{
            ui.runOnUiThread{
                val vm=ViewModelProvider(ui.activity)[DecodeSessionViewModel::class.java]
                vm.current=sample
                vm.recent.add(0,sample)
                vm.tab=4
            }
            ui.waitForIdle()
            ui.onNodeWithText(ctx.getString(R.string.language_title)).performClick()
            // Select a DIFFERENT language: tapping the currently-selected
            // option deliberately does not recreate the Activity.
            val target=if(before=="es")"en" else "es"
            val oldActivity=ui.activity
            ui.onNodeWithText(if(target=="es")"Español" else "English")
                .performClick()
            // The click must persist the preference and actually recreate the
            // activity; testing the old Activity context string after a theme
            // and configuration change can produce a stale resource value.
            ui.waitUntil(20_000){
                ui.activity.getSharedPreferences("spdecode-ui-preferences",Context.MODE_PRIVATE)
                    .getString("language","")==target
            }
            ui.waitUntil(20_000){ ui.activity!==oldActivity }
            ui.runOnIdle {
                assertEquals("New Activity should use the chosen locale",
                    target,ui.activity.resources.configuration.locales[0].language)
            }
            val active=ViewModelProvider(ui.activity)[DecodeSessionViewModel::class.java]
            assertEquals(sample.rawText,active.current?.rawText)
            assertEquals(1,active.recent.size)
        } finally {
            // This is a test-only setting: do not contaminate other tests.
            ui.activity.getSharedPreferences("spdecode-ui-preferences",Context.MODE_PRIVATE)
                .edit().putString("language",before).commit()
        }
    }
}
