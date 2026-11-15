package com.ghostdeveloper.spdecode.offline

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.ghostdeveloper.spdecode.R

/** Mirrors the online AMOLED startup; only local history and identity initialize. */
@Composable
internal fun OfflineSplashScreen(language:String) {
    Box(
        modifier=Modifier.fillMaxSize().background(Color.Black).safeDrawingPadding(),
        contentAlignment=Alignment.Center,
    ) {
        Column(
            modifier=Modifier.fillMaxWidth().padding(horizontal=24.dp),
            horizontalAlignment=Alignment.CenterHorizontally,
        ) {
            Box(
                modifier=Modifier.size(116.dp).background(
                    Color(0xFF242424),RoundedCornerShape(28.dp)),
                contentAlignment=Alignment.Center,
            ) {
                Image(
                    painter=painterResource(R.drawable.offline_launcher_foreground),
                    contentDescription="SP-DECODE",
                    modifier=Modifier.size(102.dp),
                )
            }
            Spacer(Modifier.height(24.dp))
            Text(
                "SP-DECODE",
                color=Color.White,fontSize=29.sp,
                fontWeight=FontWeight.Bold,textAlign=TextAlign.Center,
            )
            Spacer(Modifier.height(10.dp))
            Text(
                txt("splash_subtitle",language),
                color=Color(0xFFABABAB),fontSize=14.sp,
                textAlign=TextAlign.Center,
            )
            Spacer(Modifier.height(36.dp))
            CircularProgressIndicator(
                color=Color.White,strokeWidth=2.dp,
                modifier=Modifier.size(23.dp),
            )
        }
        Text(
            txt("splash_powered_by",language),
            color=Color(0xFFABABAB),
            fontSize=12.sp,textAlign=TextAlign.Center,
            modifier=Modifier.align(Alignment.BottomCenter)
                .padding(start=20.dp,end=20.dp,bottom=30.dp),
        )
    }
}
