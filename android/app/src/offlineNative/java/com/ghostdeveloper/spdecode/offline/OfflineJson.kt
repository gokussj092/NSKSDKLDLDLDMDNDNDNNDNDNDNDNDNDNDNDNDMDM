package com.ghostdeveloper.spdecode.offline

import android.content.Context
import android.graphics.Canvas
import android.graphics.Color
import android.graphics.Paint
import android.graphics.Typeface
import android.text.SpannableString
import android.text.Spanned
import android.text.style.ForegroundColorSpan
import android.view.Gravity
import android.view.View
import android.widget.TextView
import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener

/** One representation for the viewer, history, clipboard and JSON file. */
internal object OfflineJson {
    fun format(source:String):String {
        val reader=JSONTokener(source)
        val parsed=reader.nextValue()
        require(reader.nextClean()=='\u0000') { "INVALID_JSON" }
        return when(parsed) {
            is JSONObject -> parsed.toString(2)
            is JSONArray -> parsed.toString(2)
            else -> throw IllegalArgumentException("INVALID_JSON")
        }+"\n"
    }

    // Match complete strings, including escapes, before other JSON tokens.
    private val tokens=Regex("\"(?:\\\\.|[^\"\\\\])*\"|-?\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?|\\b(?:true|false|null)\\b")
    fun highlight(source:String,light:Boolean):SpannableString {
        val styled=SpannableString(source)
        for(token in tokens.findAll(source)) {
            val text=token.value
            var next=token.range.last+1
            while(next<source.length && source[next].isWhitespace())next++
            val key=text.startsWith('"') && next<source.length && source[next]==':'
            val color=when {
                key -> if(light) Color.rgb(30,86,155) else Color.rgb(124,183,249)
                text.startsWith('"') -> if(light) Color.rgb(32,107,45) else Color.rgb(152,217,160)
                text=="true" || text=="false" -> if(light) Color.rgb(112,48,158) else Color.rgb(201,160,243)
                text=="null" -> if(light) Color.rgb(153,56,79) else Color.rgb(231,165,180)
                else -> if(light) Color.rgb(145,87,20) else Color.rgb(232,182,109)
            }
            styled.setSpan(ForegroundColorSpan(color),token.range.first,token.range.last+1,
                Spanned.SPAN_EXCLUSIVE_EXCLUSIVE)
        }
        return styled
    }
}

/** Standard Android selection; numbers use the text layout's actual baselines. */
internal class OfflineJsonTextView(context:Context):TextView(context) {
    private val gutterPaint=Paint(Paint.ANTI_ALIAS_FLAG)
    private val inset=8f*resources.displayMetrics.density
    private var gutterWidth=0
    private var shownSource:String?=null
    private var shownLight:Boolean?=null

    init {
        typeface=Typeface.MONOSPACE
        textSize=13f
        includeFontPadding=false
        gravity=Gravity.TOP or Gravity.LEFT
        textDirection=View.TEXT_DIRECTION_LTR
        layoutDirection=View.LAYOUT_DIRECTION_LTR
        setHorizontallyScrolling(true)
        setTextIsSelectable(true)
        setLineSpacing(3f*resources.displayMetrics.density,1f)
    }

    fun show(source:String,light:Boolean) {
        if(source==shownSource && light==shownLight)return
        shownSource=source;shownLight=light
        setTextColor(if(light)Color.rgb(30,33,38) else Color.WHITE)
        gutterPaint.apply {
            typeface=Typeface.MONOSPACE
            textSize=this@OfflineJsonTextView.textSize
            textAlign=Paint.Align.RIGHT
            color=if(light)Color.rgb(99,106,118) else Color.rgb(145,145,145)
        }
        // A final newline is useful in files, but is not another JSON row.
        val display=source.trimEnd('\n')
        val count=display.count{it=='\n'}+1
        gutterWidth=(gutterPaint.measureText(count.toString())+inset*3).toInt()
        setPadding(gutterWidth,inset.toInt(),inset.toInt(),inset.toInt())
        text=OfflineJson.highlight(display,light)
    }

    internal fun lineBaseline(line:Int):Float = extendedPaddingTop+requireNotNull(layout).getLineBaseline(line).toFloat()

    override fun onDraw(canvas:Canvas) {
        super.onDraw(canvas)
        val lines=layout ?: return
        val first=lines.getLineForVertical((scrollY-extendedPaddingTop).coerceAtLeast(0))
        val last=lines.getLineForVertical(scrollY+height)
        for(line in first..last) {
            canvas.drawText((line+1).toString(),gutterWidth-inset*1.5f,
                lineBaseline(line),gutterPaint)
        }
    }
}
