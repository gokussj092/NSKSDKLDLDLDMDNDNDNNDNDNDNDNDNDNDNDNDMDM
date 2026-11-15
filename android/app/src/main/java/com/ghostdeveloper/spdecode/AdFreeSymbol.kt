package com.ghostdeveloper.spdecode

import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.size
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Block
import androidx.compose.material3.Icon
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/** Familiar "no ads" symbol: red prohibition mark with ADS below it. */
@Composable
internal fun AdFreeSymbol(modifier:Modifier=Modifier){
    BoxWithConstraints(modifier,contentAlignment=Alignment.Center){
        val compact=maxHeight<40.dp || maxWidth<40.dp
        Column(Modifier.fillMaxSize(),horizontalAlignment=Alignment.CenterHorizontally,
            verticalArrangement=Arrangement.Center){
            Icon(Icons.Outlined.Block,contentDescription=null,
                tint=Color(0xFFFF4545),
                modifier=Modifier.size(if(compact)18.dp else 40.dp))
            Text("ADS",
                color=Color(0xFFF6F6F6),
                fontSize=if(compact)8.sp else 16.sp,
                lineHeight=if(compact)9.sp else 17.sp,
                fontWeight=FontWeight.Black,
                maxLines=1)
        }
    }
}
