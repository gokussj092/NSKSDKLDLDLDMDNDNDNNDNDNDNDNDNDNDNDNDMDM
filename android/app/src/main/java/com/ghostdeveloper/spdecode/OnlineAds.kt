package com.ghostdeveloper.spdecode

import android.app.Activity
import android.content.Context

/** Cloud-only ad API; ordinary and Offline builds have no ad SDK. */
internal interface OnlineAds {
    fun initialize(activity:Activity)
    fun onSavedResult(activity:Activity,operationId:String,saved:Boolean)
    /** Restore a QA ad attempt when the app regains focus after file picking. */
    fun onWindowFocusChanged(activity:Activity,hasFocus:Boolean) {}
    fun showPrivacyOptions(activity:Activity)
    fun stop()
}

internal object OnlineAdsFactory {
    fun create(context:Context):OnlineAds?=try {
        val type=Class.forName("com.ghostdeveloper.spdecode.ads.UnityInterstitialHost")
        val constructor=type.getDeclaredConstructor(Context::class.java)
        constructor.isAccessible=true
        constructor.newInstance(context.applicationContext) as? OnlineAds
    }catch(_:ReflectiveOperationException){null}
     catch(_:LinkageError){null}
}
