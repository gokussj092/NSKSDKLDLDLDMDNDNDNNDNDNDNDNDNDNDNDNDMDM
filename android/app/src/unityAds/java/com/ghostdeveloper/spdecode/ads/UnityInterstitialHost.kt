package com.ghostdeveloper.spdecode.ads

import android.app.Activity
import android.content.Context
import com.unity3d.mediation.*
import com.unity3d.mediation.interstitial.LevelPlayInterstitialAd
import com.unity3d.mediation.interstitial.LevelPlayInterstitialAdListener
import java.util.concurrent.atomic.AtomicBoolean

/** Opt-in Online SDK adapter. The host must complete a real CMP flow first.
 * No decoder data, account ID, email, file name or API key enters this class.
 * Production initialization is intentionally not called by the current APK.
 */
internal class UnityInterstitialHost(context:Context) {
    data class Consent(val cmpCompleted:Boolean,val advertisingAllowed:Boolean,
        val gdprConsent:Boolean,val doNotSell:Boolean,val childDirected:Boolean)
    private val preferences=context.applicationContext.getSharedPreferences("online_ad_frequency",Context.MODE_PRIVATE)
    private var ad:LevelPlayInterstitialAd?=null
    private var enabled=false
    private var pending:(()->Unit)?=null
    private var shown=false
    private val consumed=mutableSetOf<String>()
    fun initializeAfterConsent(activity:Activity,appKey:String,adUnitId:String,consent:Consent) {
        if(!consent.cmpCompleted||!consent.advertisingAllowed||consent.childDirected||enabled)return
        if(!appKey.matches(Regex("[A-Za-z0-9_-]{6,80}"))||!adUnitId.matches(Regex("[A-Za-z0-9_-]{6,80}")))return
        LevelPlayPrivacySettings.setGDPRConsent(consent.gdprConsent)
        LevelPlayPrivacySettings.setCCPA(consent.doNotSell)
        LevelPlayPrivacySettings.setCOPPA(consent.childDirected)
        enabled=true
        LevelPlay.init(activity.applicationContext,LevelPlayInitRequest.Builder(appKey).build(),object:LevelPlayInitListener {
            override fun onInitFailed(error:LevelPlayInitError){enabled=false;finish()}
            override fun onInitSuccess(configuration:LevelPlayConfiguration){
                if(!enabled)return
                ad=LevelPlayInterstitialAd(adUnitId).also { item ->
                    item.setListener(object:LevelPlayInterstitialAdListener {
                        override fun onAdLoaded(info:LevelPlayAdInfo){}
                        override fun onAdLoadFailed(error:LevelPlayAdError){}
                        override fun onAdDisplayed(info:LevelPlayAdInfo){
                            shown=true
                            val day=System.currentTimeMillis()/86400000
                            val count=if(preferences.getLong("day",-1)==day)preferences.getInt("count",0)else 0
                            preferences.edit().putLong("last",System.currentTimeMillis()).putLong("day",day).putInt("count",count+1).apply()
                        }
                        override fun onAdDisplayFailed(error:LevelPlayAdError,info:LevelPlayAdInfo){finish()}
                        override fun onAdClicked(info:LevelPlayAdInfo){}
                        override fun onAdClosed(info:LevelPlayAdInfo){finish();if(enabled)item.loadAd()}
                        override fun onAdInfoChanged(info:LevelPlayAdInfo){}
                    });item.loadAd()
                }
            }
        })
    }
    /** Caller persists a complete result first. Skips/failures continue immediately. */
    fun showOrContinue(activity:Activity,operationId:String,success:Boolean,partial:Boolean,
        killSwitchEnabled:Boolean,onContinue:()->Unit) {
        val once=AtomicBoolean(false);val continuation={if(once.compareAndSet(false,true))onContinue()}
        val now=System.currentTimeMillis();val day=now/86400000
        val count=if(preferences.getLong("day",-1)==day)preferences.getInt("count",0)else 0
        if(!enabled||!killSwitchEnabled||!success||partial||pending!=null||
            activity.isFinishing||activity.isDestroyed||!activity.hasWindowFocus()||
            !operationId.matches(Regex("[A-Za-z0-9_-]{8,80}"))||!consumed.add(operationId)||
            now-preferences.getLong("last",0)<600000||count>=3||ad?.isAdReady()!=true) {
            continuation();return
        }
        if(consumed.size>500)consumed.clear()
        pending=continuation;shown=false
        try{ad?.showAd(activity)}catch(_:Exception){finish()}
    }
    private fun finish(){val next=pending;pending=null;next?.invoke()}
    /** Called when consent is withdrawn or the owning Activity is destroyed. */
    fun stop(){enabled=false;finish();ad=null}
}
