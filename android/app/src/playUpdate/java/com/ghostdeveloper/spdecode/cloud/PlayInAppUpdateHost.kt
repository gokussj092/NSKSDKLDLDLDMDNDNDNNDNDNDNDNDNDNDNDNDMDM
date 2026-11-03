package com.ghostdeveloper.spdecode.cloud

import android.app.Activity
import android.content.Context
import android.os.SystemClock
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.window.Dialog
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import com.ghostdeveloper.spdecode.R
import com.google.android.play.core.appupdate.AppUpdateInfo
import com.google.android.play.core.appupdate.AppUpdateManagerFactory
import com.google.android.play.core.appupdate.AppUpdateOptions
import com.google.android.play.core.install.InstallStateUpdatedListener
import com.google.android.play.core.install.model.AppUpdateType
import com.google.android.play.core.install.model.InstallStatus
import com.google.android.play.core.install.model.UpdateAvailability
import java.util.Locale

/**
 * Compiled ONLY into the Play AAB by -PspdecodePlayAab=true.
 * Play determines real eligibility, owns the Immediate UI and installs updates.
 * No Android Publisher credentials, API endpoints, or private server data here.
 */
@Composable
internal fun PlayInAppUpdateHost(
    allowPresentation: Boolean,
    language: String,
    onExclusive: (Boolean) -> Unit,
) {
    val context = LocalContext.current
    val lifecycleOwner = LocalLifecycleOwner.current
    val manager = remember(context) { AppUpdateManagerFactory.create(context) }
    val preferences = remember(context) {
        context.getSharedPreferences("spdecode-play-update-notices", Context.MODE_PRIVATE)
    }
    var offer by remember { mutableStateOf<AppUpdateInfo?>(null) }
    var downloaded by remember { mutableStateOf(false) }
    var flowRunning by remember { mutableStateOf(false) }
    var requesting by remember { mutableStateOf(false) }
    var lastCheck by remember { mutableLongStateOf(0L) }
    var lastFlowStarted by remember { mutableLongStateOf(0L) }
    var activeVersion by remember { mutableIntStateOf(0) }
    val phrases = playUpdatePhrases(language)
    val allowedNow by rememberUpdatedState(allowPresentation)
    val exclusiveCallback by rememberUpdatedState(onExclusive)

    val launcher = rememberLauncherForActivityResult(
        ActivityResultContracts.StartIntentSenderForResult()
    ) { result ->
        flowRunning = false
        exclusiveCallback(false)
        if (result.resultCode != Activity.RESULT_OK && activeVersion > 0) {
            // Cancelled Immediate/Flexible: don't prompt again in a loop.
            preferences.edit().putLong(
                "cancel_${activeVersion}", System.currentTimeMillis()
            ).apply()
            offer = null
        }
    }

    fun start(info: AppUpdateInfo, kind: Int) {
        // AppUpdateInfo is single-use; after cancellation fetch a fresh one.
        offer = null
        activeVersion = info.availableVersionCode()
        flowRunning = true
        lastFlowStarted = SystemClock.elapsedRealtime()
        exclusiveCallback(true)
        try {
            val started = manager.startUpdateFlowForResult(
                info, launcher, AppUpdateOptions.newBuilder(kind).build()
            )
            if (!started) {
                flowRunning = false
                exclusiveCallback(false)
            }
        } catch (_: Exception) {
            flowRunning = false
            exclusiveCallback(false)
        }
    }

    fun refresh(force: Boolean = false) {
        if (!allowedNow || requesting || downloaded || offer != null) return
        val now = SystemClock.elapsedRealtime()
        if (!force && lastCheck != 0L && now - lastCheck < 60_000L) return
        lastCheck = now
        requesting = true
        manager.appUpdateInfo.addOnSuccessListener { info ->
            requesting = false
            if (!allowedNow) return@addOnSuccessListener
            if (info.installStatus() == InstallStatus.DOWNLOADED) {
                downloaded = true
                exclusiveCallback(true)
                return@addOnSuccessListener
            }
            if (info.installStatus() == InstallStatus.PENDING ||
                info.installStatus() == InstallStatus.DOWNLOADING ||
                info.installStatus() == InstallStatus.INSTALLING) {
                // Flexible download is already managed by Google Play.
                return@addOnSuccessListener
            }
            if (info.updateAvailability() ==
                UpdateAvailability.DEVELOPER_TRIGGERED_UPDATE_IN_PROGRESS) {
                if (info.isUpdateTypeAllowed(AppUpdateType.IMMEDIATE) &&
                    SystemClock.elapsedRealtime() - lastFlowStarted > 5_000L) {
                    start(info, AppUpdateType.IMMEDIATE)
                }
                return@addOnSuccessListener
            }
            if (info.updateAvailability() != UpdateAvailability.UPDATE_AVAILABLE) return@addOnSuccessListener
            val code = info.availableVersionCode()
            val nowMillis = System.currentTimeMillis()
            if (nowMillis - preferences.getLong("cancel_$code", 0L) < 60L * 60 * 1000) {
                return@addOnSuccessListener
            }
            if (info.updatePriority() >= 4 &&
                info.isUpdateTypeAllowed(AppUpdateType.IMMEDIATE)) {
                start(info, AppUpdateType.IMMEDIATE)
            } else if (info.isUpdateTypeAllowed(AppUpdateType.FLEXIBLE) &&
                nowMillis - preferences.getLong("later_$code", 0L) >= 24L * 60 * 60 * 1000) {
                offer = info
                activeVersion = code
                exclusiveCallback(true)
            }
        }.addOnFailureListener {
            requesting = false
            // Play may be unavailable (side-loaded, offline, or ineligible).
            // Do not emulate its availability using Cloud version numbers.
        }
    }

    DisposableEffect(manager) {
        val listener = InstallStateUpdatedListener { state ->
            if (state.installStatus() == InstallStatus.DOWNLOADED) {
                downloaded = true
                offer = null
                flowRunning = false
                exclusiveCallback(true)
            }
        }
        // On a side-loaded AAB or a device without working Play services,
        // failure to register is nonfatal; availability remains Play-owned.
        val registered = runCatching { manager.registerListener(listener) }.isSuccess
        onDispose {
            if (registered) runCatching { manager.unregisterListener(listener) }
            exclusiveCallback(false)
        }
    }
    DisposableEffect(lifecycleOwner, allowPresentation) {
        val observer = LifecycleEventObserver { _, event ->
            if (event == Lifecycle.Event.ON_RESUME && allowPresentation) {
                refresh(force = true)
            }
        }
        lifecycleOwner.lifecycle.addObserver(observer)
        onDispose { lifecycleOwner.lifecycle.removeObserver(observer) }
    }
    LaunchedEffect(allowPresentation) {
        if (allowPresentation) refresh()
    }

    if (allowPresentation && downloaded) {
        PlayUpdateDialog(
            title = phrases.readyTitle,
            subtitle = phrases.play,
            detail = phrases.readyBody,
            version = null,
            primary = phrases.restart,
            secondary = phrases.later,
            onPrimary = {
                manager.completeUpdate().addOnFailureListener {
                    // Keep the install-ready notice for retry.
                    downloaded = true
                }
            },
            onSecondary = {
                downloaded = false
                exclusiveCallback(false)
                // Play retains the DOWNLOADED state for the next foreground entry.
            },
        )
    } else if (allowPresentation && offer != null) {
        val info = offer!!
        PlayUpdateDialog(
            title = phrases.title,
            subtitle = phrases.available,
            detail = phrases.body,
            version = "${phrases.build} ${info.availableVersionCode()}",
            primary = phrases.update,
            secondary = phrases.later,
            onPrimary = { start(info, AppUpdateType.FLEXIBLE) },
            onSecondary = {
                preferences.edit().putLong(
                    "later_${info.availableVersionCode()}", System.currentTimeMillis()
                ).apply()
                offer = null
                exclusiveCallback(false)
            },
        )
    }
}

private data class PlayUpdatePhrases(
    val title: String, val available: String, val body: String,
    val play: String, val update: String, val later: String,
    val readyTitle: String, val readyBody: String, val restart: String,
    val build: String,
)

private fun playUpdatePhrases(tag: String): PlayUpdatePhrases {
    val lang = (if (tag == "system") Locale.getDefault().language else tag)
        .substringBefore('-').substringBefore('_').lowercase(Locale.ROOT)
    // All supported SP-DECODE locales, without downloading strings from the VPS.
    val entries = mapOf(
        "es" to listOf("Nueva actualización","Disponible en Google Play","Hay una nueva versión con mejoras y correcciones.","Actualización mediante Google Play","Actualizar ahora","Más tarde","Actualización lista","La descarga terminó. Reinicia para instalarla.","Reiniciar e instalar","Build"),
        "en" to listOf("New update","Available on Google Play","A new version with improvements and fixes is available.","Update via Google Play","Update now","Later","Update ready","The download is complete. Restart to install.","Restart and install","Build"),
        "pt" to listOf("Nova atualização","Disponível no Google Play","Uma nova versão com melhorias e correções está disponível.","Atualização pelo Google Play","Atualizar agora","Mais tarde","Atualização pronta","Download concluído. Reinicie para instalar.","Reiniciar e instalar","Build"),
        "ar" to listOf("تحديث جديد","متاح على Google Play","يتوفر إصدار جديد يتضمن تحسينات وإصلاحات.","التحديث عبر Google Play","تحديث الآن","لاحقًا","التحديث جاهز","اكتمل التنزيل. أعد التشغيل للتثبيت.","إعادة التشغيل والتثبيت","الإصدار"),
        "fa" to listOf("به‌روزرسانی جدید","موجود در Google Play","نسخه جدیدی با بهبودها و اصلاحات در دسترس است.","به‌روزرسانی از Google Play","اکنون به‌روزرسانی کن","بعداً","به‌روزرسانی آماده است","بارگیری پایان یافت. برای نصب راه‌اندازی مجدد کنید.","راه‌اندازی مجدد و نصب","ساخت"),
        "fr" to listOf("Nouvelle mise à jour","Disponible sur Google Play","Une nouvelle version avec des améliorations et correctifs est disponible.","Mise à jour via Google Play","Mettre à jour","Plus tard","Mise à jour prête","Téléchargement terminé. Redémarrez pour installer.","Redémarrer et installer","Build"),
        "in" to listOf("Pembaruan baru","Tersedia di Google Play","Versi baru dengan peningkatan dan perbaikan tersedia.","Pembaruan melalui Google Play","Perbarui sekarang","Nanti","Pembaruan siap","Unduhan selesai. Mulai ulang untuk memasang.","Mulai ulang dan pasang","Build"),
        "ru" to listOf("Новое обновление","Доступно в Google Play","Доступна новая версия с улучшениями и исправлениями.","Обновление через Google Play","Обновить сейчас","Позже","Обновление готово","Загрузка завершена. Перезапустите для установки.","Перезапустить и установить","Сборка"),
        "de" to listOf("Neues Update","In Google Play verfügbar","Eine neue Version mit Verbesserungen und Fehlerbehebungen ist verfügbar.","Update über Google Play","Jetzt aktualisieren","Später","Update bereit","Download abgeschlossen. Zum Installieren neu starten.","Neustart und Installation","Build"),
        "tr" to listOf("Yeni güncelleme","Google Play'de mevcut","İyileştirmeler ve düzeltmeler içeren yeni sürüm hazır.","Google Play üzerinden güncelleme","Şimdi güncelle","Daha sonra","Güncelleme hazır","İndirme tamamlandı. Yüklemek için yeniden başlatın.","Yeniden başlat ve yükle","Derleme"),
        "vi" to listOf("Bản cập nhật mới","Có trên Google Play","Đã có phiên bản mới với các cải tiến và sửa lỗi.","Cập nhật qua Google Play","Cập nhật ngay","Để sau","Đã tải xong","Đã tải xuống. Khởi động lại để cài đặt.","Khởi động lại và cài đặt","Bản dựng"),
        "hi" to listOf("नया अपडेट","Google Play पर उपलब्ध","सुधारों और बग फ़िक्स के साथ नया संस्करण उपलब्ध है।","Google Play से अपडेट करें","अभी अपडेट करें","बाद में","अपडेट तैयार है","डाउनलोड पूरा हुआ। इंस्टॉल करने के लिए पुनः आरंभ करें।","पुनः आरंभ करें और इंस्टॉल करें","बिल्ड"),
        "ja" to listOf("新しいアップデート","Google Playで利用可能","改善と修正を含む新しいバージョンがあります。","Google Playから更新","今すぐ更新","後で","更新の準備完了","ダウンロードが完了しました。再起動してインストールしてください。","再起動してインストール","ビルド"),
        "it" to listOf("Nuovo aggiornamento","Disponibile su Google Play","È disponibile una nuova versione con miglioramenti e correzioni.","Aggiornamento tramite Google Play","Aggiorna ora","Più tardi","Aggiornamento pronto","Download completato. Riavvia per installare.","Riavvia e installa","Build")
    )
    val e = entries[lang] ?: entries.getValue("en")
    return PlayUpdatePhrases(e[0],e[1],e[2],e[3],e[4],e[5],e[6],e[7],e[8],e[9])
}

@Composable
private fun PlayUpdateDialog(
    title: String, subtitle: String, detail: String, version: String?,
    primary: String, secondary: String, onPrimary: () -> Unit, onSecondary: () -> Unit,
) {
    Dialog(onDismissRequest = onSecondary) {
        Surface(
            color = Color(0xFF242424),
            shape = RoundedCornerShape(25.dp),
            border = BorderStroke(1.dp, Color(0xFF363636)),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(
                modifier = Modifier.padding(22.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp),
            ) {
                Row(verticalAlignment = Alignment.CenterVertically) {
                    Image(painterResource(R.drawable.ic_launcher_foreground),null,Modifier.size(48.dp))
                    Spacer(Modifier.width(12.dp))
                    Column {
                        Text(title,color=Color(0xFFF7F7F7),
                            fontWeight=FontWeight.Bold,fontSize=21.sp)
                        Text(subtitle,color=Color(0xFFABABAB),fontSize=13.sp)
                    }
                }
                HorizontalDivider(color=Color(0xFF383838))
                Text("SP-DECODE" + (version?.let { " · $it" } ?: ""),
                    color=Color.White,fontWeight=FontWeight.SemiBold,fontSize=16.sp)
                Text(detail,color=Color(0xFFBCBCBC),fontSize=14.sp,
                    lineHeight=21.sp,textAlign=TextAlign.Start)
                Text("Google Play",color=Color(0xFFABABAB),fontSize=12.sp)
                Button(
                    onClick=onPrimary,modifier=Modifier.fillMaxWidth(),
                    colors=ButtonDefaults.buttonColors(
                        containerColor=Color(0xFFF7F7F7),contentColor=Color.Black),
                ) { Text(primary,fontWeight=FontWeight.SemiBold) }
                OutlinedButton(
                    onClick=onSecondary,modifier=Modifier.fillMaxWidth(),
                    border=BorderStroke(1.dp,Color(0xFF505050)),
                    colors=ButtonDefaults.outlinedButtonColors(contentColor=Color(0xFFBCBCBC)),
                ) { Text(secondary) }
            }
        }
    }
}
