package com.ghostdeveloper.spdecode.ads

import android.app.Activity
import android.content.Context
import android.os.SystemClock
import android.util.Log
import android.widget.Toast
import com.ghostdeveloper.spdecode.BuildConfig
import com.ghostdeveloper.spdecode.OnlineAds
import com.google.android.ump.ConsentInformation
import com.google.android.ump.ConsentRequestParameters
import com.google.android.ump.UserMessagingPlatform
import com.unity3d.mediation.*
import com.unity3d.mediation.interstitial.LevelPlayInterstitialAd
import com.unity3d.mediation.interstitial.LevelPlayInterstitialAdListener
import java.lang.ref.WeakReference
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
    private var lastLoadRequestedElapsed=Long.MIN_VALUE
    private val qaEveryFile=BuildConfig.SPDECODE_ADS_EVERY_FILE_QA
    private var lastAdErrorCode:Int?=null
    private data class DeferredAdAttempt(
        val operationId:String,
        val success:Boolean,
        val createdElapsed:Long,
    )
    private var deferredAttempt:DeferredAdAttempt?=null
    private var deferredActivity:WeakReference<Activity>?=null

    /** QA only: let the file picker/overlays release focus before showing. */
    private fun deferAd(activity:Activity,operationId:String,success:Boolean,reason:String){
        deferredAttempt=DeferredAdAttempt(operationId,success,SystemClock.elapsedRealtime())
        deferredActivity=WeakReference(activity)
        Log.i(LOG_TAG,"ad_deferred_$reason")
        showQaFeedback(activity,if(reason=="window_focus") "esperando foco" else "cargando anuncio")
    }
    private fun clearDeferred(){
        deferredAttempt=null
        deferredActivity=null
    }
    override fun onWindowFocusChanged(activity:Activity,hasFocus:Boolean){
        if(!qaEveryFile||!hasFocus||stopped)return
        // A short posting delay lets Android finish the picker-to-Activity transition.
        activity.window.decorView.postDelayed({flushDeferred(activity)},150L)
    }
    private fun flushDeferred(activity:Activity){
        if(!qaEveryFile)return
        val attempt=deferredAttempt?:return
        if(deferredActivity?.get()!==activity)return
        if(stopped||activity.isFinishing||activity.isDestroyed||
            SystemClock.elapsedRealtime()-attempt.createdElapsed>DEFERRED_AD_TTL_MS){
            Log.i(LOG_TAG,"ad_deferred_expired")
            clearDeferred()
            return
        }
        if(!activity.hasWindowFocus())return
        if(!enabled||!consentInformation.canRequestAds()){
            Log.i(LOG_TAG,"ad_deferred_not_permitted")
            clearDeferred()
            showQaFeedback(activity,"LevelPlay o UMP no disponible")
            return
        }
        requestLoadWhenReady()
        if(ad?.isAdReady()!=true){
            Log.i(LOG_TAG,"ad_deferred_waiting_for_load")
            if(!loading&&lastAdErrorCode!=null)
                showQaFeedback(activity,"sin anuncio, error ${lastAdErrorCode}")
            else showQaFeedback(activity,"cargando anuncio")
            return
        }
        clearDeferred()
        Log.i(LOG_TAG,"ad_deferred_ready")
        showOrContinue(activity,attempt.operationId,attempt.success,partial=false,
            killSwitchEnabled=consentInformation.canRequestAds(),onContinue={})
    }
    private fun showQaFeedback(activity:Activity,detail:String){
        if(!qaEveryFile||activity.isFinishing||activity.isDestroyed)return
        if(BuildConfig.DEBUG) Toast.makeText(activity.applicationContext,"Anuncios QA: $detail",Toast.LENGTH_SHORT).show()
    }
    private companion object {
        const val LOG_TAG="SPDECODE_ADS"
        const val MAX_DAILY_ADS=12
        const val MIN_INTERVAL_MS=240_000L
        const val LOAD_RETRY_MS=45_000L
        const val LOAD_COOLDOWN_MS=60_000L
        const val DEFERRED_AD_TTL_MS=30_000L
    }
    private fun requestLoadWhenReady(){
        val item=ad ?: return
        val now=SystemClock.elapsedRealtime()
        // Throttle network ad *loads*, not user-visible decode/catalog results.
        // No timer or automatic polling: next eligible result/close requests a load.
        if(stopped||!enabled||loading||item.isAdReady()||
            now<retryAfterElapsed||
            (lastLoadRequestedElapsed!=Long.MIN_VALUE &&
                now-lastLoadRequestedElapsed<LOAD_COOLDOWN_MS))return
        loading=true
        lastLoadRequestedElapsed=now
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
        // QA is triggered by a successful file decode even if history persistence failed.
        showOrContinue(activity,operationId,success=(saved||qaEveryFile),partial=false,
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
                lastAdErrorCode=error.errorCode
                Log.w(LOG_TAG,"levelplay_init_failed_code_${error.errorCode}")
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
                            lastAdErrorCode=null
                            Log.i(LOG_TAG,"ad_loaded")
                            deferredActivity?.get()?.let { active ->
                                active.window.decorView.post {flushDeferred(active)}
                            }
                        }
                        override fun onAdLoadFailed(error:LevelPlayAdError){
                            loading=false
                            lastAdErrorCode=error.errorCode
                            retryAfterElapsed=SystemClock.elapsedRealtime()+LOAD_RETRY_MS
                            Log.w(LOG_TAG,"ad_load_failed_code_${error.errorCode}_retry_later")
                            deferredActivity?.get()?.let { active ->
                                showQaFeedback(active,"sin anuncio, error ${error.errorCode}")
                            }
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
                            lastAdErrorCode=error.errorCode
                            Log.w(LOG_TAG,"ad_display_failed_code_${error.errorCode}")
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
                flushDeferred(activity)
            }
        })
    }
    /** Caller persists a complete result first. Skips/failures continue immediately. */
    fun showOrContinue(activity:Activity,operationId:String,success:Boolean,partial:Boolean,
        killSwitchEnabled:Boolean,onContinue:()->Unit) {
        val once=AtomicBoolean(false);val continuation={if(once.compareAndSet(false,true))onContinue()}
        // A failed initial auction must not disable all future ads in this session.
        requestLoadWhenReady()
        if(qaEveryFile&&success&&!partial&&killSwitchEnabled&&
            !activity.isFinishing&&!activity.isDestroyed&&
            operationId.matches(Regex("[A-Za-z0-9_-]{8,80}"))){
            if(!activity.hasWindowFocus()){
                deferAd(activity,operationId,success,"window_focus")
                continuation()
                return
            }
            if(enabled&&ad?.isAdReady()!=true){
                deferAd(activity,operationId,success,"ad_loading")
                continuation()
                return
            }
        }
        val now=System.currentTimeMillis();val day=now/86400000
        val count=if(preferences.getLong("day",-1)==day)preferences.getInt("count",0)else 0
        val blockedByPacing=!qaEveryFile&&now-preferences.getLong("last",0)<MIN_INTERVAL_MS
        val blockedByDailyCap=!qaEveryFile&&count>=MAX_DAILY_ADS
        if(!enabled||!killSwitchEnabled||!success||partial||pending!=null||
            activity.isFinishing||activity.isDestroyed||!activity.hasWindowFocus()||
            !operationId.matches(Regex("[A-Za-z0-9_-]{8,80}"))||!consumed.add(operationId)||
            blockedByPacing||blockedByDailyCap||ad?.isAdReady()!=true) {
            Log.i(LOG_TAG,when{
                !enabled->"skip_not_initialized"
                !killSwitchEnabled->"skip_consent"
                !success||partial->"skip_no_saved_result"
                blockedByDailyCap->"skip_daily_cap"
                blockedByPacing->"skip_pacing"
                ad?.isAdReady()!=true->"skip_not_loaded"
                else->"skip_other"
            })
            val feedback=when{
                !killSwitchEnabled->"UMP no permite anuncios"
                !enabled->"LevelPlay no inicializado"
                !success||partial->"resultado no valido"
                pending!=null->"otro anuncio activo"
                !activity.hasWindowFocus()->"pantalla sin foco"
                blockedByDailyCap->"limite diario alcanzado"
                blockedByPacing->"esperando intervalo"
                ad?.isAdReady()!=true&&lastAdErrorCode!=null->"sin anuncio, error ${lastAdErrorCode}"
                ad?.isAdReady()!=true&&loading->"cargando anuncio"
                ad?.isAdReady()!=true->"anuncio no disponible"
                else->"presentacion omitida"
            }
            showQaFeedback(activity,feedback)
            continuation();return
        }
        if(consumed.size>500)consumed.clear()
        pending=continuation;shown=false
        try{
            Log.i(LOG_TAG,"ad_show_requested")
            ad?.showAd(activity)
        }catch(_:Exception){
            Log.w(LOG_TAG,"ad_show_exception")
            showQaFeedback(activity,"error al mostrar anuncio")
            finish()
        }
    }
    private fun finish(){val next=pending;pending=null;next?.invoke()}
    /** Called when consent is withdrawn or the owning Activity is destroyed. */
    override fun stop(){
        stopped=true
        enabled=false
        loading=false
        clearDeferred()
        finish()
        ad=null
    }
}
