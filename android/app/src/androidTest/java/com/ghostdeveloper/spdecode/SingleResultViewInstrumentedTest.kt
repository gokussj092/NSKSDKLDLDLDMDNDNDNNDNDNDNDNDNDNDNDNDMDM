package com.ghostdeveloper.spdecode

import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.onNodeWithText
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/** The screenshot-approved single decoder view has no duplicate panels. */
@RunWith(AndroidJUnit4::class)
class SingleResultViewInstrumentedTest {
    @get:Rule val ui=createComposeRule()
    private val ctx get()=InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun jsonOnlyDataUnderDecoderAndDateCommentHeader() {
        val raw="┌───────────────\n│SP-DECODE (.ehi)\n"+
            "│[۞] configMessage: demo value\n"+
            "│[۞] overwriteServerData: {\"city\":\"LA\",\"port\":443}\n"+
            "└───────────────"
        val view=DecodeView("sample.ehi","ehi",raw,200)
        ui.setContent {
            CompleteResultCard(
                current=view,reveal=false,hideCredentials=false,
                onReveal={},onCopy={},onExport={})
        }
        ui.onNodeWithText(ctx.getString(R.string.result_decoded_by,"SP-DECODE"),substring=true).assertExists()
        ui.onNodeWithText(ctx.getString(R.string.result_decoded_by,"HTTP Injector"),substring=true).assertDoesNotExist()
        val surface=continuousJsonView(ui)
        ui.runOnIdle { org.junit.Assert.assertTrue(visibleJsonText(surface).contains("\"city\": \"LA\"")) }
        ui.onNodeWithText(ctx.getString(R.string.detailed_fields)).assertDoesNotExist()
        ui.onNodeWithText(ctx.getString(R.string.raw_text)).assertDoesNotExist()
        ui.onNodeWithText(ctx.getString(R.string.copy)).assertExists()
        ui.onNodeWithText(ctx.getString(R.string.export)).assertExists()
    }
}

