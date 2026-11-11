package com.ghostdeveloper.spdecode.ads

import android.app.Activity
import android.content.Context
import android.os.SystemClock
import android.util.Log
import com.ghostdeveloper.spdecode.BuildConfig
import com.ghostdeveloper.spdecode.OnlineAds
import com.google.android.ump.ConsentInformation
import com.google.android.ump.ConsentRequestParameters
import com.google.android.ump.UserMessagingPlatform
import com.unity3d.mediation.*
import com.unity3d.mediation.interstitial.LevelPlayInterstitialAd
import com.unity3d.mediation.interstitial.LevelPlayInterstitialAdListener
import java.util.concurrent.atomic.AtomicBoolean

/** Online-only UMP consent and Unity LevelPlay host.
 * No file, decoded data, email, account identifier or API key enters the SDK.
 */
internal class UnityInterstitialHost(context:Context):OnlineAds {
    data class Consent(val cmpCompleted:Boolean,val advertisingAllowed:Boolean,
        val gdprConsent:Boolean,val doNotSell:Boolean,val childDirected:Boolean)
    private val preferences=context.applicationContext.getSharedPreferences("online_ad_frequency",Context.MODE_PRIVATE)
    private var ad:LevelPlayInterstitialAd?=null
    private var enabled=false
    private var pending:(()->Unit)?=null
    private var shown=false
    private val consumed=mutableSetOf<String>()
    private var consentRequested=false
    private var stopped=false
    private var loading=false
    private var retryAfterElapsed=0L
    private companion object {
        const val LOG_TAG="SPDECODE_ADS"
        const val MAX_DAILY_ADS=12
        const val MIN_INTERVAL_MS=240_000L
        const val LOAD_RETRY_MS=45_000L
    }
    private fun requestLoadWhenReady(){
        val item=ad ?: return
        if(stopped||!enabled||loading||item.isAdReady()||
            SystemClock.elapsedRealtime()<retryAfterElapsed)return
        loading=true
        try{
            Log.i(LOG_TAG,"load_requested")
            item.loadAd()
        }catch(_:RuntimeException){
            loading=false
            retryAfterElapsed=SystemClock.elapsedRealtime()+LOAD_RETRY_MS
            Log.w(LOG_TAG,"load_exception_retry_later")
        }
    }
    private val consentInformation=UserMessagingPlatform.getConsentInformation(context.applicationContext)

    override fun initialize(activity:Activity) {
        if(consentRequested||stopped||!BuildConfig.SPDECODE_UNITY_ADS_ENABLED)return
        consentRequested=true
        val params=ConsentRequestParameters.Builder().build()
        try {
            Log.i(LOG_TAG,"ump_update_requested")
            consentInformation.requestConsentInfoUpdate(activity,params,{
                Log.i(LOG_TAG,"ump_updated")
                // Consent from a previous session may already permit requests.
                initializeIfPermitted(activity)
                UserMessagingPlatform.loadAndShowConsentFormIfRequired(activity) { error ->
                    if(error!=null)Log.w(LOG_TAG,"ump_form_error")
                    initializeIfPermitted(activity)
                }
            },{
                Log.w(LOG_TAG,"ump_update_error")
                initializeIfPermitted(activity) // Prior-session status, if still valid.
            })
        }catch(_:RuntimeException){
            Log.w(LOG_TAG,"ump_exception")
        }
    }

    private fun initializeIfPermitted(activity:Activity) {
        if(stopped||enabled||activity.isFinishing||activity.isDestroyed)return
        if(!consentInformation.canRequestAds()){
            Log.i(LOG_TAG,"consent_not_ready")
            return
        }
        initializeAfterConsent(activity,BuildConfig.SPDECODE_UNITY_APP_KEY,
            BuildConfig.SPDECODE_UNITY_INTERSTITIAL_ID,
            Consent(cmpCompleted=true,advertisingAllowed=true,
                gdprConsent=consentInformation.consentStatus==ConsentInformation.ConsentStatus.OBTAINED,
                doNotSell=true,childDirected=false))
    }

    override fun showPrivacyOptions(activity:Activity) {
        if(stopped||!consentRequested)return
        if(consentInformation.privacyOptionsRequirementStatus!=
            ConsentInformation.PrivacyOptionsRequirementStatus.REQUIRED)return
        UserMessagingPlatform.showPrivacyOptionsForm(activity){ _ ->
            if(!consentInformation.canRequestAds()){
                enabled=false
                ad=null
                finish()
            }else{
                LevelPlayPrivacySettings.setGDPRConsent(
                    consentInformation.consentStatus==ConsentInformation.ConsentStatus.OBTAINED)
                LevelPlayPrivacySettings.setCCPA(true)
            }
        }
    }

    override fun onSavedResult(activity:Activity,operationId:String,saved:Boolean) {
        showOrContinue(activity,operationId,success=saved,partial=false,
            killSwitchEnabled=consentInformation.canRequestAds(),onContinue={})
    }
    fun initializeAfterConsent(activity:Activity,appKey:String,adUnitId:String,consent:Consent) {
        if(!consent.cmpCompleted||!consent.advertisingAllowed||consent.childDirected||enabled)return
        if(!appKey.matches(Regex("[A-Za-z0-9_-]{6,80}"))||!adUnitId.matches(Regex("[A-Za-z0-9_-]{6,80}")))return
        LevelPlayPrivacySettings.setGDPRConsent(consent.gdprConsent)
        LevelPlayPrivacySettings.setCCPA(consent.doNotSell)
        LevelPlayPrivacySettings.setCOPPA(consent.childDirected)
        enabled=true
        Log.i(LOG_TAG,"levelplay_init_requested")
        LevelPlay.init(activity.applicationContext,LevelPlayInitRequest.Builder(appKey).build(),object:LevelPlayInitListener {
            override fun onInitFailed(error:LevelPlayInitError){
                Log.w(LOG_TAG,"levelplay_init_failed")
                enabled=false
                consentRequested=false // Allow a later retry after network recovery.
                ad=null
                loading=false
                finish()
            }
            override fun onInitSuccess(configuration:LevelPlayConfiguration){
                if(!enabled||stopped)return
                Log.i(LOG_TAG,"levelplay_init_ok")
                ad=LevelPlayInterstitialAd(adUnitId).also { item ->
                    item.setListener(object:LevelPlayInterstitialAdListener {
                        override fun onAdLoaded(info:LevelPlayAdInfo){
                            loading=false
                            Log.i(LOG_TAG,"ad_loaded")
                        }
                        override fun onAdLoadFailed(error:LevelPlayAdError){
                            loading=false
                            retryAfterElapsed=SystemClock.elapsedRealtime()+LOAD_RETRY_MS
                            Log.w(LOG_TAG,"ad_load_failed_retry_later")
                        }
                        override fun onAdDisplayed(info:LevelPlayAdInfo){
                            shown=true
                            loading=false
                            Log.i(LOG_TAG,"ad_displayed")
                            val day=System.currentTimeMillis()/86400000
                            val count=if(preferences.getLong("day",-1)==day)preferences.getInt("count",0)else 0
                            preferences.edit().putLong("last",System.currentTimeMillis()).putLong("day",day).putInt("count",count+1).apply()
                        }
                        override fun onAdDisplayFailed(error:LevelPlayAdError,info:LevelPlayAdInfo){
                            Log.w(LOG_TAG,"ad_display_failed")
                            finish()
                            requestLoadWhenReady()
                        }
                        override fun onAdClicked(info:LevelPlayAdInfo){}
                        override fun onAdClosed(info:LevelPlayAdInfo){
                            Log.i(LOG_TAG,"ad_closed")
                            finish()
                            requestLoadWhenReady()
                        }
                        override fun onAdInfoChanged(info:LevelPlayAdInfo){}
                    })
                }
                requestLoadWhenReady()
            }
        })
    }
    /** Caller persists a complete result first. Skips/failures continue immediately. */
    fun showOrContinue(activity:Activity,operationId:String,success:Boolean,partial:Boolean,
        killSwitchEnabled:Boolean,onContinue:()->Unit) {
        val once=AtomicBoolean(false);val continuation={if(once.compareAndSet(false,true))onContinue()}
        // A failed initial auction must not disable all future ads in this session.
        requestLoadWhenReady()
        val now=System.currentTimeMillis();val day=now/86400000
        val count=if(preferences.getLong("day",-1)==day)preferences.getInt("count",0)else 0
        if(!enabled||!killSwitchEnabled||!success||partial||pending!=null||
            activity.isFinishing||activity.isDestroyed||!activity.hasWindowFocus()||
            !operationId.matches(Regex("[A-Za-z0-9_-]{8,80}"))||!consumed.add(operationId)||
            now-preferences.getLong("last",0)<MIN_INTERVAL_MS||
            count>=MAX_DAILY_ADS||ad?.isAdReady()!=true) {
            Log.i(LOG_TAG,when{
                !enabled->"skip_not_initialized"
                !killSwitchEnabled->"skip_consent"
                !success||partial->"skip_no_saved_result"
                count>=MAX_DAILY_ADS->"skip_daily_cap"
                now-preferences.getLong("last",0)<MIN_INTERVAL_MS->"skip_pacing"
                ad?.isAdReady()!=true->"skip_not_loaded"
                else->"skip_other"
            })
            continuation();return
        }
        if(consumed.size>500)consumed.clear()
        pending=continuation;shown=false
        try{
            Log.i(LOG_TAG,"ad_show_requested")
            ad?.showAd(activity)
        }catch(_:Exception){
            Log.w(LOG_TAG,"ad_show_exception")
            finish()
        }
    }
    private fun finish(){val next=pending;pending=null;next?.invoke()}
    /** Called when consent is withdrawn or the owning Activity is destroyed. */
    override fun stop(){stopped=true;enabled=false;loading=false;finish();ad=null}
}
