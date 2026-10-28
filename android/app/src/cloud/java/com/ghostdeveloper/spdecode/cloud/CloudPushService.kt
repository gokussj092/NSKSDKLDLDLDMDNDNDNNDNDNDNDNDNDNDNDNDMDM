package com.ghostdeveloper.spdecode.cloud

import android.content.ContentProvider
import android.content.ContentValues
import android.database.Cursor
import android.net.Uri
import com.ghostdeveloper.spdecode.BuildConfig
import com.google.firebase.FirebaseApp
import com.google.firebase.FirebaseOptions
import com.google.firebase.messaging.FirebaseMessaging
import com.google.firebase.messaging.FirebaseMessagingService
import com.google.firebase.messaging.RemoteMessage

/** Startup installs a callback, never starts Firebase before explicit opt-in. */
class CloudPushInitializer:ContentProvider() {
    override fun onCreate():Boolean {
        val c=context?.applicationContext?:return false
        CloudNoticePush.configure={ctx,enabled->
            if(BuildConfig.NOTICE_FIREBASE_APP_ID.isNotEmpty() && (!enabled||CloudLegalConsent.accepted(ctx))) {
                val app=FirebaseApp.getApps(ctx).firstOrNull()?:if(enabled)FirebaseApp.initializeApp(ctx,FirebaseOptions.Builder()
                    .setApplicationId(BuildConfig.NOTICE_FIREBASE_APP_ID).setApiKey(BuildConfig.NOTICE_FIREBASE_API_KEY)
                    .setProjectId(BuildConfig.NOTICE_FIREBASE_PROJECT_ID).setGcmSenderId(BuildConfig.NOTICE_FIREBASE_SENDER_ID).build()) else null
                if(app!=null) {
                    val messaging=FirebaseMessaging.getInstance();messaging.isAutoInitEnabled=enabled
                    if(enabled)messaging.subscribeToTopic("spdecode-notices-v1").addOnCompleteListener { }
                    else {messaging.unsubscribeFromTopic("spdecode-notices-v1").addOnCompleteListener {messaging.deleteToken()}}
                }
            }
        }
        if(CloudNotifications.enabled(c)&&CloudLegalConsent.accepted(c))CloudNoticePush.configure(c,true)
        return true
    }
    override fun query(u:Uri,p:Array<out String>?,s:String?,a:Array<out String>?,o:String?):Cursor?=null
    override fun getType(u:Uri):String?=null
    override fun insert(u:Uri,v:ContentValues?):Uri?=null
    override fun delete(u:Uri,s:String?,a:Array<out String>?):Int=0
    override fun update(u:Uri,v:ContentValues?,s:String?,a:Array<out String>?):Int=0
}
class CloudPushService:FirebaseMessagingService() {
    override fun onMessageReceived(message:RemoteMessage) {
        CloudNotifications.hint(applicationContext,message.data["noticeId"].orEmpty())
    }
    override fun onNewToken(token:String) {
        if(CloudNotifications.enabled(this)&&CloudLegalConsent.accepted(this))CloudNoticePush.configure(this,true)
    }
}
