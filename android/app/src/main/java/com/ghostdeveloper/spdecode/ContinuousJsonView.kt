package com.ghostdeveloper.spdecode

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Typeface
import android.os.Bundle
import android.view.GestureDetector
import android.view.MotionEvent
import android.view.View
import android.view.ViewConfiguration
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityNodeInfo
import android.widget.OverScroller
import com.ghostdeveloper.spdecode.results.NativeResultEngine
import kotlin.math.ceil
import kotlin.math.floor
import kotlin.math.max
import kotlin.math.min
import kotlin.math.roundToInt

/**
 * A continuous code surface. The gutter and code share one baseline and scroll
 * offset, so neither wrapping nor independently measured Texts can misalign them.
 * No StaticLayout/AnnotatedString is built for a whole document or huge scalar.
 */
internal class ContinuousJsonView(
    context: Context,
    private val document: NativeResultEngine.Document,
    private val mask: Boolean,
) : View(context) {
    private val density = resources.displayMetrics.density
    private val paint = Paint(Paint.ANTI_ALIAS_FLAG).apply {
        typeface = Typeface.MONOSPACE
        textSize = 13f * resources.displayMetrics.scaledDensity
    }
    private val metrics = paint.fontMetrics
    internal val rowHeight = max(19f * resources.displayMetrics.scaledDensity,
        metrics.descent - metrics.ascent + 2f * density)
    private val cellWidth = paint.measureText("M")
    private val inset = 8f * density
    private val gutter = paint.measureText(document.lineCount.toString()) + 2f * inset
    private val scroller = OverScroller(context)
    private var offsetX = 0f
    private var offsetY = 0f
    private var downX = 0f
    private var downY = 0f
    private val touchSlop = ViewConfiguration.get(context).scaledTouchSlop
    private var dragging = false
    private val windows = object : LinkedHashMap<Long, org.json.JSONObject>(96, .75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<Long, org.json.JSONObject>?) = size > 96
    }
    private val gestures = GestureDetector(context, object : GestureDetector.SimpleOnGestureListener() {
        override fun onDown(event: MotionEvent): Boolean {
            scroller.forceFinished(true)
            return true
        }
        override fun onScroll(first: MotionEvent?, last: MotionEvent, distanceX: Float, distanceY: Float): Boolean {
            // Let the surrounding screen continue scrolling at the document edge.
            val canMove = if (kotlin.math.abs(distanceY) >= kotlin.math.abs(distanceX))
                canScrollVertically(if (distanceY > 0) 1 else -1)
            else canScrollHorizontally(if (distanceX > 0) 1 else -1)
            parent?.requestDisallowInterceptTouchEvent(canMove)
            moveTo(offsetX + distanceX, offsetY + distanceY)
            return true
        }
        override fun onFling(first: MotionEvent?, last: MotionEvent, velocityX: Float, velocityY: Float): Boolean {
            scroller.fling(offsetX.roundToInt(), offsetY.roundToInt(),
                -velocityX.roundToInt(), -velocityY.roundToInt(), 0, maxX().roundToInt(), 0, maxY().roundToInt())
            postInvalidateOnAnimation()
            return true
        }
        override fun onSingleTapUp(event: MotionEvent): Boolean = performClick()
    })

    init {
        setBackgroundColor(Color.BLACK)
        isFocusable = true
        isVerticalScrollBarEnabled = true
        isHorizontalScrollBarEnabled = true
        importantForAccessibility = IMPORTANT_FOR_ACCESSIBILITY_YES
        tag = "continuous-json"
    }

    private fun maxX() = max(0f, document.columnCount * cellWidth - (width - gutter - inset).coerceAtLeast(1f))
    private fun maxY() = max(0f, document.lineCount * rowHeight + 2f * inset - height)

    private fun moveTo(x: Float, y: Float) {
        offsetX = x.coerceIn(0f, maxX())
        offsetY = y.coerceIn(0f, maxY())
        awakenScrollBars()
        invalidate()
    }

    internal fun scrollToLine(line: Int) {
        scroller.forceFinished(true)
        moveTo(offsetX, line.coerceIn(0, document.lineCount - 1) * rowHeight)
    }
    internal fun scrollToColumn(column: Int) = moveTo(column.coerceAtLeast(0) * cellWidth, offsetY)
    internal fun lineBaseline(line: Int) = inset + line * rowHeight - offsetY - metrics.ascent
    internal fun visibleWindow(line: Int): org.json.JSONObject {
        val column = max(0, floor(offsetX / cellWidth).toInt() - 1)
        val count = ceil((width - gutter).coerceAtLeast(1f) / cellWidth).toInt().coerceIn(1, 1023) * 2 + 2
        val key = (line.toLong() shl 32) or column.toLong()
        return windows.getOrPut(key) { document.lineWindow(line, column, count, mask) }
    }

    override fun onSizeChanged(w: Int, h: Int, oldw: Int, oldh: Int) {
        windows.clear()
        moveTo(offsetX, offsetY)
    }

    override fun onDraw(canvas: Canvas) {
        super.onDraw(canvas)
        val first = max(0, floor((offsetY - inset) / rowHeight).toInt())
        val last = min(document.lineCount - 1, ceil((offsetY + height - inset) / rowHeight).toInt())
        for (line in first..last) {
            val baseline = lineBaseline(line)
            // The exact same baseline is used for this line's number and code.
            paint.color = Color.rgb(145, 145, 145)
            paint.textAlign = Paint.Align.RIGHT
            canvas.drawText((line + 1).toString(), gutter - inset, baseline, paint)
            paint.textAlign = Paint.Align.LEFT
            val window = visibleWindow(line)
            val text = window.getString("text")
            val start = window.getInt("column")
            val valueColumn = window.getInt("valueColumn")
            val keyEnd = textIndex(text, valueColumn - 2 - start)
            val valueStart = textIndex(text, valueColumn - start)
            val x = gutter + start * cellWidth - offsetX
            canvas.save()
            canvas.clipRect(gutter, 0f, width.toFloat(), height.toFloat())
            drawRun(canvas, text, 0, keyEnd, x, baseline, Color.rgb(124, 183, 249))
            drawRun(canvas, text, keyEnd, valueStart, x, baseline, Color.WHITE)
            val color = when (window.getString("type")) {
                "string", "text" -> Color.rgb(152, 217, 160)
                "number" -> Color.rgb(232, 182, 109)
                "boolean" -> Color.rgb(201, 160, 243)
                "null" -> Color.rgb(231, 165, 180)
                else -> Color.WHITE
            }
            drawRun(canvas, text, valueStart, text.length, x, baseline, color)
            canvas.restore()
        }
        paint.color = Color.rgb(41, 41, 41)
        canvas.drawLine(gutter - inset / 2, 0f, gutter - inset / 2, height.toFloat(), paint)
    }

    private fun textIndex(text: String, column: Int): Int {
        var index = 0
        var cells = 0
        while (index < text.length && cells < column) {
            val point = text.codePointAt(index)
            val count = if (point < 128 || point == 0x2022) 1 else 2
            if (cells + count > column) break
            cells += count
            index += Character.charCount(point)
        }
        return index
    }

    internal fun visibleTextRight(line: Int): Float {
        val window = visibleWindow(line)
        return gutter + window.getInt("column") * cellWidth - offsetX + paint.measureText(window.getString("text"))
    }

    private fun drawRun(canvas: Canvas, text: String, start: Int, end: Int, x: Float, y: Float, color: Int) {
        if (start >= end) return
        paint.color = color
        canvas.drawText(text, start, end, x + paint.measureText(text, 0, start), y, paint)
    }

    override fun onTouchEvent(event: MotionEvent): Boolean {
        if (event.actionMasked == MotionEvent.ACTION_DOWN) {
            downX = event.x; downY = event.y; dragging = false
            parent?.requestDisallowInterceptTouchEvent(maxX() > 0 || maxY() > 0)
        } else if (event.actionMasked == MotionEvent.ACTION_MOVE && !dragging) {
            if (kotlin.math.abs(event.x - downX) > touchSlop || kotlin.math.abs(event.y - downY) > touchSlop) {
                dragging = true
                parent?.requestDisallowInterceptTouchEvent(true)
            }
        }
        val handled = gestures.onTouchEvent(event)
        if (event.actionMasked == MotionEvent.ACTION_UP || event.actionMasked == MotionEvent.ACTION_CANCEL) {
            parent?.requestDisallowInterceptTouchEvent(false)
            dragging = false
        }
        return handled || super.onTouchEvent(event)
    }

    override fun performClick(): Boolean { super.performClick(); return true }
    override fun canScrollVertically(direction: Int) = if (direction < 0) offsetY > 0 else offsetY < maxY()
    override fun canScrollHorizontally(direction: Int) = if (direction < 0) offsetX > 0 else offsetX < maxX()
    override fun computeVerticalScrollRange() = (document.lineCount * rowHeight + inset * 2).roundToInt()
    override fun computeVerticalScrollOffset() = offsetY.roundToInt()
    override fun computeHorizontalScrollRange() = (document.columnCount * cellWidth + gutter + inset).roundToInt()
    override fun computeHorizontalScrollOffset() = offsetX.roundToInt()
    override fun computeScroll() {
        if (scroller.computeScrollOffset()) {
            moveTo(scroller.currX.toFloat(), scroller.currY.toFloat())
            postInvalidateOnAnimation()
        }
    }

    override fun onInitializeAccessibilityNodeInfo(info: AccessibilityNodeInfo) {
        super.onInitializeAccessibilityNodeInfo(info)
        info.className = "android.widget.TextView"
        info.isScrollable = true
        val first = max(0, floor(offsetY / rowHeight).toInt())
        val last = min(document.lineCount - 1, first + ceil(height / rowHeight).toInt())
        info.text = (first..last).joinToString("\n") { "${it + 1} ${visibleWindow(it).getString("text")}" }
        if (canScrollVertically(1)) info.addAction(AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_FORWARD)
        if (canScrollVertically(-1)) info.addAction(AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_BACKWARD)
        if (canScrollHorizontally(1)) info.addAction(AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_RIGHT)
        if (canScrollHorizontally(-1)) info.addAction(AccessibilityNodeInfo.AccessibilityAction.ACTION_SCROLL_LEFT)
    }

    override fun performAccessibilityAction(action: Int, arguments: Bundle?): Boolean {
        when (action) {
            AccessibilityNodeInfo.ACTION_SCROLL_FORWARD -> moveTo(offsetX, offsetY + height - rowHeight)
            AccessibilityNodeInfo.ACTION_SCROLL_BACKWARD -> moveTo(offsetX, offsetY - height + rowHeight)
            android.R.id.accessibilityActionScrollRight -> moveTo(offsetX + width - gutter, offsetY)
            android.R.id.accessibilityActionScrollLeft -> moveTo(offsetX - width + gutter, offsetY)
            else -> return super.performAccessibilityAction(action, arguments)
        }
        sendAccessibilityEvent(AccessibilityEvent.TYPE_VIEW_SCROLLED)
        return true
    }

    override fun onDetachedFromWindow() {
        scroller.forceFinished(true)
        windows.clear()
        super.onDetachedFromWindow()
    }
}
