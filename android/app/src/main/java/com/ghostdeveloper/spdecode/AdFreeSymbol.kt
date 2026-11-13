package com.ghostdeveloper.spdecode

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Block
import androidx.compose.material.icons.outlined.Campaign
import androidx.compose.material3.Icon
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color

/** Advertising crossed out, rather than a generic account-security shield. */
@Composable
internal fun AdFreeSymbol(modifier:Modifier=Modifier){
    Box(modifier,contentAlignment=Alignment.Center){
        Icon(Icons.Outlined.Campaign,null,
            tint=Color(0xFFB8DCC0),modifier=Modifier.fillMaxSize(0.77f))
        Box(Modifier.align(Alignment.BottomEnd)
            .fillMaxSize(0.40f)
            .background(Color(0xFF222222),CircleShape),
            contentAlignment=Alignment.Center){
            Icon(Icons.Outlined.Block,null,
                tint=Color(0xFFFF7070),modifier=Modifier.fillMaxSize())
        }
    }
}
