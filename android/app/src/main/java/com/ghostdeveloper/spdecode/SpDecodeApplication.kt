package com.ghostdeveloper.spdecode

import android.app.Application
import android.content.Context

/** A small explicit composition root. No reflection, networking or secret logs. */
interface HistoryServices {
    val records: HistoryRepository
    val preferences: HistoryPreferences
}

class OfflineHistoryServices(context:Context):HistoryServices {
    private val app=context.applicationContext
    override val records:HistoryRepository by lazy { HistoryRepository.create(app) }
    override val preferences:HistoryPreferences by lazy { HistoryPreferences(app) }
}

class SpDecodeApplication:Application() {
    val services:HistoryServices by lazy { OfflineHistoryServices(this) }
    override fun onCreate() {
        super.onCreate()
        // Optional service notices are initialized by the Cloud provider after opt-in.
    }
}

