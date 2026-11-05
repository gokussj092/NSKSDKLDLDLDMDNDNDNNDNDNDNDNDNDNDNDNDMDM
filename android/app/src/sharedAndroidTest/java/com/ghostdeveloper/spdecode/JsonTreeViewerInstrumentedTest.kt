package com.ghostdeveloper.spdecode

import android.graphics.Bitmap
import android.graphics.Canvas
import android.view.View
import android.view.ViewGroup
import android.view.MotionEvent
import android.os.SystemClock
import android.view.accessibility.AccessibilityNodeInfo
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.Modifier
import androidx.compose.ui.test.junit4.ComposeContentTestRule
import androidx.compose.ui.test.junit4.createComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.runner.lifecycle.ActivityLifecycleMonitorRegistry
import androidx.test.runner.lifecycle.Stage
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

internal fun continuousJsonView(ui: ComposeContentTestRule): ContinuousJsonView {
    var result: ContinuousJsonView? = null
    fun find(view: View): ContinuousJsonView? {
        if (view is ContinuousJsonView) return view
        if (view is ViewGroup) for (index in 0 until view.childCount) find(view.getChildAt(index))?.let { return it }
        return null
    }
    ui.waitUntil(timeoutMillis = 20000) {
        ui.runOnIdle {
            result = ActivityLifecycleMonitorRegistry.getInstance().getActivitiesInStage(Stage.RESUMED)
                .firstNotNullOfOrNull { find(it.window.decorView) }
        }
        result != null
    }
    return requireNotNull(result)
}

internal fun visibleJsonText(view: ContinuousJsonView): String {
    val info = AccessibilityNodeInfo.obtain()
    try { view.onInitializeAccessibilityNodeInfo(info); return info.text.toString() }
    finally { info.recycle() }
}

private fun captureJsonView(view: ContinuousJsonView, name: String) {
    val bitmap = Bitmap.createBitmap(view.width, view.height, Bitmap.Config.ARGB_8888)
    try {
        view.draw(Canvas(bitmap))
        val directory = view.context.filesDir.resolve("viewer-qa").apply { mkdirs() }
        directory.resolve("$name.png").outputStream().use { bitmap.compress(Bitmap.CompressFormat.PNG, 100, it) }
    } finally { bitmap.recycle() }
}

/** The actual Android surface: continuous scroll, complete values and shared baselines. */
@RunWith(AndroidJUnit4::class)
class JsonTreeViewerInstrumentedTest {
    @get:Rule val ui = createComposeRule()
    private val ctx get() = InstrumentationRegistry.getInstrumentation().targetContext

    @Test fun nestedObjectsAreVisibleImmediatelyWithoutExpansion() {
        val raw = """{"host":"vpn.test","nested":{"city":"LA","port":443,"active":true}}"""
        ui.setContent { JsonTreeViewer(raw, "hc", false, "nested") }
        val view = continuousJsonView(ui)
        ui.runOnIdle {
            val text = visibleJsonText(view)
            assertTrue(text.contains("\"city\": \"LA\""))
            assertTrue(text.contains("\"port\": 443"))
            assertFalse(text.contains("{…}"))
            assertEquals(view.rowHeight, view.lineBaseline(5) - view.lineBaseline(4), .01f)
            captureJsonView(view, "nested")
        }
    }

    @Test fun fiftyThousandRecordsReachTheFinalLineWithCorrectNumbers() {
        val count = 50000
        val raw = (0 until count).joinToString(",", "[", "]") { "{\"id\":$it}" }
        ui.setContent {
            Column(Modifier.verticalScroll(rememberScrollState())) { JsonTreeViewer(raw, "json", false, "large") }
        }
        val view = continuousJsonView(ui)
        ui.runOnIdle {
            val before = view.lineBaseline(0)
            val time = SystemClock.uptimeMillis()
            for ((step, action) in listOf(MotionEvent.ACTION_DOWN, MotionEvent.ACTION_MOVE, MotionEvent.ACTION_UP).withIndex()) {
                val event = MotionEvent.obtain(time, time + step * 60L, action, view.width / 2f,
                    view.height * if (step == 0) .8f else .2f, 0)
                view.dispatchTouchEvent(event); event.recycle()
            }
            assertTrue(view.lineBaseline(0) < before)
            view.scrollToLine(3 * count + 1)
            val text = visibleJsonText(view)
            assertTrue(text.contains("${3 * count}     \"id\": ${count - 1}"))
            assertTrue(text.contains("${3 * count + 2} ]"))
            captureJsonView(view, "large-tail")
        }
    }

    @Test fun hugeScalarAndLongKeyRemainReadableThroughHorizontalScroll() {
        val raw = "{\"${"k".repeat(3500)}\":\"${"x".repeat(200000)}🌎LAST_CHARACTER\"}"
        ui.setContent { JsonTreeViewer(raw, "json", false, "long") }
        val view = continuousJsonView(ui)
        ui.runOnIdle {
            view.scrollToColumn(Int.MAX_VALUE)
            assertTrue(view.visibleWindow(1).getString("text").contains("LAST_CHARACTER"))
            captureJsonView(view, "long-value-tail")
        }
    }

    @Test fun privacyToggleReplacesTheViewAndClearsVisibleSecrets() {
        val raw = """{"password":"FICTIONAL_ONLY","nested":{"password":"NESTED_SECRET"}}"""
        val mask = mutableStateOf(false)
        ui.setContent { JsonTreeViewer(raw, "json", mask.value, "privacy") }
        val clear = continuousJsonView(ui)
        ui.runOnIdle { assertTrue(visibleJsonText(clear).contains("FICTIONAL_ONLY")); mask.value = true }
        val hidden = continuousJsonView(ui)
        ui.runOnIdle {
            assertNotSame(clear, hidden)
            val text = visibleJsonText(hidden)
            assertFalse(text.contains("FICTIONAL_ONLY"))
            assertFalse(text.contains("NESTED_SECRET"))
            assertTrue(text.contains("••••••••"))
        }
    }

    @Test fun resultCardKeepsCopyExportAndFilename() {
        val raw = """{"nested":{"city":"LA"}}"""
        ui.setContent {
            CompleteResultCard(DecodeView("sample.hc", "hc", raw, raw.length),
                false, false, {}, {}, {})
        }
        val view = continuousJsonView(ui)
        ui.runOnIdle { assertTrue(visibleJsonText(view).contains("\"city\": \"LA\"")) }
        ui.onNodeWithText("sample.hc").assertExists()
        ui.onNodeWithText(ctx.getString(R.string.copy)).assertExists()
        ui.onNodeWithText(ctx.getString(R.string.export)).assertExists()
    }
}
