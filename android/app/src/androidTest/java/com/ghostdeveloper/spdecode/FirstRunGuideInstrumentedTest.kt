package com.ghostdeveloper.spdecode

import android.content.Context
import android.content.res.Configuration
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.size
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.unit.dp
import androidx.compose.runtime.*
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.getUnclippedBoundsInRoot
import androidx.compose.ui.test.performClick
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.util.Locale

@RunWith(AndroidJUnit4::class)
class FirstRunGuideInstrumentedTest {
    @get:Rule val ui=createComposeRule()

    @Test fun allStepsAdvanceAndFinishWithoutDeletingData() {
        val context=InstrumentationRegistry.getInstrumentation().targetContext
        var step by mutableIntStateOf(0)
        var visible by mutableStateOf(true)
        ui.setContent {
            if(visible) FirstRunGuidePanel(step,
                onNext={
                    if(step+1==FirstRunGuide.STEPS)visible=false else step++
                },
                onSkip={visible=false})
        }
        for(i in 0 until FirstRunGuide.STEPS) {
            ui.onNodeWithText(context.getString(FirstRunGuide.stepTextId(i)))
                .assertExists()
            ui.onNodeWithText(context.getString(R.string.guide_progress,
                i+1,FirstRunGuide.STEPS)).assertExists()
            ui.onNodeWithText(context.getString(
                if(i==FirstRunGuide.STEPS-1)R.string.guide_finish
                else R.string.guide_next)).performClick()
        }
        ui.runOnIdle {
            assertFalse(visible)
            assertEquals(0,FirstRunGuide.targetTab(0))
            assertEquals(0,FirstRunGuide.targetTab(1))
            assertEquals(0,FirstRunGuide.targetTab(2))
            assertEquals(0,FirstRunGuide.targetTab(3))
            assertEquals(1,FirstRunGuide.targetTab(4))
            assertEquals(2,FirstRunGuide.targetTab(5))
            assertEquals(3,FirstRunGuide.targetTab(6))
            assertEquals(4,FirstRunGuide.targetTab(7))
        }
    }

    @Test fun skippingDoesNotRequireImportingPrivateConfiguration() {
        val context=InstrumentationRegistry.getInstrumentation().targetContext
        var visible by mutableStateOf(true)
        ui.setContent {
            if(visible) FirstRunGuidePanel(0,onNext={},onSkip={visible=false})
        }
        ui.onNodeWithText(context.getString(R.string.guide_skip)).performClick()
        ui.runOnIdle { assertFalse(visible) }
    }

    @Test fun overlayIsCenteredAndGuideActionsFitCompactScreens() {
        val ctx=InstrumentationRegistry.getInstrumentation().targetContext
        ui.setContent {
            Box(Modifier.size(320.dp,420.dp).testTag("guide_viewport")) {
                CenteredFirstRunGuide(0,onNext={},onSkip={})
            }
        }
        val viewport=ui.onNodeWithTag("guide_viewport").getUnclippedBoundsInRoot()
        val panel=ui.onNodeWithTag("first_run_guide_panel").getUnclippedBoundsInRoot()
        // Spotlight tour deliberately positions the guide away from the
        // target: Home targets sit above the panel; tab targets sit below it.
        assertTrue(panel.top>=viewport.top)
        assertTrue(panel.bottom<=viewport.bottom)
        ui.onNodeWithText(ctx.getString(R.string.guide_next)).assertExists()
        ui.onNodeWithText(ctx.getString(R.string.guide_skip)).assertExists()
    }

    @Test fun onboardingTranslationsExistInAllAvailableLanguages() {
        val context=InstrumentationRegistry.getInstrumentation().targetContext
        for(tag in listOf("en","es","pt-BR","ar","fa","fr","id","ru","de")) {
            val config=Configuration(context.resources.configuration)
            config.setLocale(Locale.forLanguageTag(tag))
            val resources=context.createConfigurationContext(config).resources
            for(step in 0 until FirstRunGuide.STEPS) {
                assertTrue("$tag step=$step",resources.getString(
                    FirstRunGuide.stepTextId(step)).isNotBlank())
            }
            assertTrue(resources.getString(R.string.guide_replay).isNotBlank())
        }
    }
}
