package com.ghostdeveloper.spdecode

import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableIntStateOf
import androidx.compose.runtime.mutableStateListOf
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.lifecycle.ViewModel

/** UI session state; durable encrypted records are managed by SecureDecodeHistory. */
class DecodeSessionViewModel:ViewModel(){
    val recent=mutableStateListOf<DecodeView>()
    var current by mutableStateOf<DecodeView?>(null)
    var tab by mutableIntStateOf(0)
    var reveal by mutableStateOf(false)
    var stagedResultExport:Pair<DecodeView,ResultExport>?=null
}
