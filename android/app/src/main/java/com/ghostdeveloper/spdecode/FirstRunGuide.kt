package com.ghostdeveloper.spdecode

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.foundation.Canvas
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.geometry.Rect
import androidx.compose.ui.geometry.RoundRect
import androidx.compose.ui.geometry.CornerRadius
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.PathFillType
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.layout.onGloballyPositioned
import androidx.compose.ui.layout.boundsInWindow
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * Non-blocking, local first-use coach marks. Each step highlights its relevant
 * existing control and can navigate to the corresponding screen. No network.
 * The Activity records completion in private SharedPreferences.
 */
internal object FirstRunGuide {
    // Visit all Home controls before moving to the next tab, once each.
    const val STEPS = 8

    fun targetTab(step: Int): Int = when (step) {
        in 0..3 -> 0  // File, text, Cloud, result
        4 -> 1        // History
        5 -> 2        // Formats
        6 -> 3        // Servidores VPN
        7 -> 4        // Settings
        else -> 0
    }

    fun stepTextId(step: Int): Int = when (step) {
        0 -> R.string.guide_step_one
        1 -> R.string.guide_step_two
        2 -> R.string.guide_step_three
        3 -> R.string.guide_step_four
        4 -> R.string.guide_step_five
        5 -> R.string.guide_step_six
        6 -> R.string.guide_step_seven
        else -> R.string.guide_step_eight
    }
}

/** Window-space bounds of controls displayed below the guide scrim. */
internal object GuideSpotlightTargets {
    val rectangles=mutableStateMapOf<Int,Rect>()
    fun locate(step:Int,bounds:Rect){rectangles[step]=bounds}
}

/** Center the onboarding overlay in the available content viewport. */
@Composable
internal fun CenteredFirstRunGuide(step: Int, onNext: () -> Unit, onSkip: () -> Unit) {
    var windowOrigin by remember { mutableStateOf(Offset.Zero) }
    val bounds=GuideSpotlightTargets.rectangles[step]
    BoxWithConstraints(
        modifier=Modifier.fillMaxSize().onGloballyPositioned {
            windowOrigin=it.boundsInWindow().topLeft
        },
        contentAlignment=Alignment.Center,
    ) {
        Canvas(Modifier.fillMaxSize()) {
            val target=bounds?.translate(-windowOrigin.x,-windowOrigin.y)
            // Render a real cutout, not a border hidden beneath the overlay.
            val mask=Path().apply {
                fillType=PathFillType.EvenOdd
                addRect(Rect(Offset.Zero,size))
                if(target!=null && target.width>1f && target.height>1f)
                    addRoundRect(RoundRect(target,CornerRadius(13.dp.toPx())))
            }
            drawPath(mask,Color.Black.copy(alpha=0.82f))
            if(target!=null && target.width>1f && target.height>1f) {
                drawRoundRect(
                    color=Color(0xFF80E6FF),
                    topLeft=target.topLeft,
                    size=target.size,
                    cornerRadius=CornerRadius(13.dp.toPx()),
                    style=Stroke(width=3.dp.toPx()),
                )
                drawRoundRect(
                    color=Color.White.copy(alpha=0.65f),
                    topLeft=target.topLeft,
                    size=target.size,
                    cornerRadius=CornerRadius(13.dp.toPx()),
                    style=Stroke(width=1.dp.toPx()),
                )
            }
        }
        FirstRunGuidePanel(
            step=step,onNext=onNext,onSkip=onSkip,
            modifier=Modifier.align(if(step<=3)Alignment.BottomCenter else Alignment.TopCenter)
                .padding(top=28.dp,bottom=76.dp)
                .heightIn(max=(maxHeight-108.dp).coerceAtLeast(0.dp)),
        )
    }
}

@Composable
internal fun FirstRunGuidePanel(
    step: Int,
    onNext: () -> Unit,
    onSkip: () -> Unit,
    modifier: Modifier=Modifier,
) {
    Surface(
        modifier=modifier.fillMaxWidth().padding(horizontal=13.dp, vertical=6.dp).testTag("first_run_guide_panel"),
        color=Color(0xFF242424),
        shape=RoundedCornerShape(17.dp),
        border=BorderStroke(1.dp,Color(0xFF565656)),
        shadowElevation=7.dp,
    ) {
        Column(Modifier.verticalScroll(rememberScrollState()).padding(horizontal=17.dp,vertical=13.dp),
            verticalArrangement=Arrangement.spacedBy(8.dp)) {
            Row(verticalAlignment=Alignment.CenterVertically) {
                Icon(Icons.Outlined.TipsAndUpdates, null,
                    tint=Color.White,modifier=Modifier.size(20.dp))
                Spacer(Modifier.width(8.dp))
                Text(stringResource(R.string.guide_title),
                    color=Color.White,fontWeight=FontWeight.Bold,
                    fontSize=16.sp,modifier=Modifier.weight(1f))
                Text(stringResource(R.string.guide_progress,step+1,FirstRunGuide.STEPS),
                    color=Color(0xFFB5B5B5),fontSize=12.sp)
            }
            Text(stringResource(FirstRunGuide.stepTextId(step)),
                color=Color(0xFFD5D5D5),fontSize=13.sp,lineHeight=19.sp)
            Row(modifier=Modifier.fillMaxWidth(),
                horizontalArrangement=Arrangement.End,
                verticalAlignment=Alignment.CenterVertically) {
                TextButton(onClick=onSkip) {
                    Text(stringResource(R.string.guide_skip),
                        color=Color(0xFFBDBDBD))
                }
                Spacer(Modifier.width(6.dp))
                Button(onClick=onNext,shape=RoundedCornerShape(11.dp),
                    colors=ButtonDefaults.buttonColors(
                        containerColor=Color(0xFFF5F5F5),
                        contentColor=Color.Black)) {
                    Text(stringResource(
                        if(step==FirstRunGuide.STEPS-1)R.string.guide_finish
                        else R.string.guide_next))
                }
            }
        }
    }
}
