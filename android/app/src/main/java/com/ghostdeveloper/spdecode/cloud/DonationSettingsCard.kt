package com.ghostdeveloper.spdecode.cloud

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.drawscope.withTransform
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.ghostdeveloper.spdecode.R

@Composable
internal fun DonationSettingsCard() {
    val context=LocalContext.current
    Card(shape=RoundedCornerShape(18.dp),colors=CardDefaults.cardColors(
        containerColor=MaterialTheme.colorScheme.surfaceVariant)) {
        Column(Modifier.fillMaxWidth().padding(16.dp),verticalArrangement=Arrangement.spacedBy(10.dp)) {
            Text(stringResource(R.string.donations_title),style=MaterialTheme.typography.titleMedium)
            ListItem(headlineContent={Text("Binance")},
                supportingContent={Text("Ghost Developer\nID: 1233239512")},
                leadingContent={DonationIcon(false)},trailingContent={
                    TextButton(onClick={
                        (context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager)
                            .setPrimaryClip(ClipData.newPlainText("Binance ID","1233239512"))
                        Toast.makeText(context,R.string.donation_id_copied,Toast.LENGTH_SHORT).show()
                    }){Text(stringResource(R.string.donation_copy_id))}
                },colors=ListItemDefaults.colors(containerColor=MaterialTheme.colorScheme.surfaceVariant))
            HorizontalDivider(color=MaterialTheme.colorScheme.outlineVariant)
            ListItem(headlineContent={Text("PayPal")},
                supportingContent={Text(stringResource(R.string.donation_coming_soon))},
                leadingContent={DonationIcon(true)},
                colors=ListItemDefaults.colors(containerColor=MaterialTheme.colorScheme.surfaceVariant))
        }
    }
}

/** Monochrome payment marks keep the existing AMOLED palette. */
@Composable
private fun DonationIcon(paypal:Boolean) {
    val color=MaterialTheme.colorScheme.onSurface
    Canvas(Modifier.size(28.dp)) {
        withTransform({scale(size.width/24f,size.height/24f,pivot=Offset.Zero)}) {
            if(paypal) {
                val p=Path().apply {
                    moveTo(7f,2f);lineTo(15f,2f);cubicTo(23f,2f,21f,13f,14f,13f)
                    lineTo(10f,13f);lineTo(8.5f,22f);lineTo(3.5f,22f);close()
                    moveTo(11f,6f);lineTo(10.5f,9f);lineTo(14f,9f)
                    cubicTo(17f,9f,17f,6f,14.5f,6f);close()
                }
                p.fillType=androidx.compose.ui.graphics.PathFillType.EvenOdd
                drawPath(p,color)
            }else {
                fun diamond(x:Float,y:Float,r:Float) {
                    drawPath(Path().apply {moveTo(x,y-r);lineTo(x+r,y);lineTo(x,y+r);lineTo(x-r,y);close()},color)
                }
                diamond(12f,12f,2.6f);diamond(3f,12f,2.6f);diamond(21f,12f,2.6f)
                drawPath(Path().apply {moveTo(5.7f,6.3f);lineTo(12f,0f);lineTo(18.3f,6.3f)
                    lineTo(15.7f,8.9f);lineTo(12f,5.2f);lineTo(8.3f,8.9f);close()},color)
                drawPath(Path().apply {moveTo(5.7f,17.7f);lineTo(12f,24f);lineTo(18.3f,17.7f)
                    lineTo(15.7f,15.1f);lineTo(12f,18.8f);lineTo(8.3f,15.1f);close()},color)
            }
        }
    }
}
