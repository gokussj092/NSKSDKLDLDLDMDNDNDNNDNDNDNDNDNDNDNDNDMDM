package com.ghostdeveloper.spdecode

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.util.Locale

internal object CommerceGiftText {
    private val en=listOf("Redeem gift code","Gift code","Redeem","Gift redeemed",
        "Invalid or expired code","Already redeemed","Too many attempts",
        "Sign in to redeem","View my account","Credits added","Ad-free access activated",
        "Offline license activated","Please try again")
    private val es=listOf("Canjear código de regalo","Código de regalo","Canjear","Regalo canjeado",
        "Código inválido o vencido","Ya canjeaste este código","Demasiados intentos",
        "Inicia sesión para canjear","Ver mi cuenta","Créditos añadidos",
        "Acceso sin anuncios activado","Licencia Offline activada","Inténtalo de nuevo")
    private val other=mapOf(
        "pt" to "Resgatar código de presente|Código de presente|Resgatar|Presente resgatado|Código inválido ou expirado|Código já usado|Muitas tentativas|Entre para resgatar|Ver minha conta|Créditos adicionados|Acesso sem anúncios ativado|Licença Offline ativada|Tente novamente",
        "fr" to "Utiliser un code cadeau|Code cadeau|Utiliser|Cadeau utilisé|Code invalide ou expiré|Code déjà utilisé|Trop de tentatives|Connectez-vous|Voir mon compte|Crédits ajoutés|Accès sans pub activé|Licence Offline activée|Réessayez",
        "de" to "Geschenkcode einlösen|Geschenkcode|Einlösen|Geschenk eingelöst|Code ungültig oder abgelaufen|Bereits eingelöst|Zu viele Versuche|Zum Einlösen anmelden|Mein Konto|Credits hinzugefügt|Werbefrei aktiviert|Offline-Lizenz aktiviert|Erneut versuchen",
        "it" to "Riscatta codice regalo|Codice regalo|Riscatta|Regalo riscattato|Codice non valido o scaduto|Codice già usato|Troppi tentativi|Accedi per riscattare|Vai al mio account|Crediti aggiunti|Accesso senza annunci attivo|Licenza Offline attiva|Riprova",
        "ru" to "Активировать подарочный код|Подарочный код|Активировать|Подарок активирован|Код недействителен|Код уже использован|Слишком много попыток|Войдите для активации|Мой аккаунт|Кредиты добавлены|Без рекламы активировано|Offline-лицензия активирована|Повторите попытку",
        "tr" to "Hediye kodunu kullan|Hediye kodu|Kullan|Hediye kullanıldı|Geçersiz veya süresi dolmuş kod|Kod zaten kullanıldı|Çok fazla deneme|Kullanmak için giriş yap|Hesabım|Krediler eklendi|Reklamsız erişim etkin|Offline lisans etkin|Tekrar dene",
        "ar" to "استرداد رمز الهدية|رمز الهدية|استرداد|تم استرداد الهدية|رمز غير صالح أو منتهي|تم استخدام الرمز|محاولات كثيرة|سجل الدخول للاسترداد|حسابي|تمت إضافة الرصيد|تم تفعيل بدون إعلانات|تم تفعيل ترخيص Offline|حاول مجددًا",
        "fa" to "بازخرید کد هدیه|کد هدیه|بازخرید|هدیه ثبت شد|کد نامعتبر یا منقضی|کد قبلاً استفاده شد|تلاش بیش از حد|برای بازخرید وارد شوید|حساب من|اعتبار اضافه شد|بدون تبلیغ فعال شد|مجوز Offline فعال شد|دوباره تلاش کنید",
        "hi" to "उपहार कोड रिडीम करें|उपहार कोड|रिडीम|उपहार रिडीम हुआ|अमान्य या समाप्त कोड|कोड पहले उपयोग हुआ|बहुत प्रयास हुए|लॉगिन कर रिडीम करें|मेरा खाता|क्रेडिट जोड़ दिए गए|विज्ञापन मुक्त सक्रिय|Offline लाइसेंस सक्रिय|फिर कोशिश करें",
        "ja" to "ギフトコードを使用|ギフトコード|使用|ギフトを適用しました|無効または期限切れのコード|使用済みコード|試行回数が多すぎます|ログインして使用|マイアカウント|クレジットを追加|広告なし有効|Offlineライセンス有効|もう一度お試しください",
        "id" to "Tukarkan kode hadiah|Kode hadiah|Tukarkan|Hadiah berhasil ditukar|Kode tidak valid atau kedaluwarsa|Kode sudah ditukar|Terlalu banyak percobaan|Masuk untuk menukar|Akun saya|Kredit ditambahkan|Tanpa iklan aktif|Lisensi Offline aktif|Coba lagi",
        "vi" to "Đổi mã quà tặng|Mã quà tặng|Đổi mã|Đã nhận quà|Mã sai hoặc hết hạn|Mã đã sử dụng|Quá nhiều lần thử|Đăng nhập để nhận|Tài khoản của tôi|Đã thêm tín dụng|Đã bật không quảng cáo|Đã kích hoạt Offline|Thử lại"
    ).mapValues{it.value.split("|")}
    fun get(lang:String,key:String):String{
        val pos=en.indexOf(key);if(pos<0)return key
        return when(lang.lowercase(Locale.ROOT)){
            "es"->es[pos]
            "in"->other["id"]?.getOrNull(pos)?:key
            else->other[lang.lowercase(Locale.ROOT)]?.getOrNull(pos)?:key
        }
    }
}
@Composable
internal fun CommerceGiftRedeemPage(language:String,auth:NativeCommerceAuth,
    onSignIn:()->Unit,onAccount:()->Unit){
    val tr:(String)->String={CommerceGiftText.get(language,it)}
    val scope=rememberCoroutineScope()
    var code by remember {mutableStateOf("")}
    var busy by remember {mutableStateOf(false)}
    var error by remember {mutableStateOf<String?>(null)}
    var redeemed by remember {mutableStateOf<JSONObject?>(null)}
    val valid=Regex("SPG-[A-Za-z0-9_-]{22}").matches(code.trim())
    Column(verticalArrangement=Arrangement.spacedBy(18.dp)){
        Text(tr("Redeem gift code"),fontSize=27.sp,fontWeight=FontWeight.Bold,
            color=Color.White)
        Column(Modifier.fillMaxWidth().background(Color(0xFF222222),
            RoundedCornerShape(24.dp)).padding(22.dp),
            horizontalAlignment=Alignment.CenterHorizontally,
            verticalArrangement=Arrangement.spacedBy(18.dp)){
            Icon(Icons.Outlined.CardGiftcard,null,
                tint=Color(0xFFB8DCC0),modifier=Modifier.size(58.dp))
            if(redeemed==null){
                OutlinedTextField(value=code,onValueChange={
                    code=it.trim().take(32);error=null
                },modifier=Modifier.fillMaxWidth(),singleLine=true,
                    label={Text(tr("Gift code"))},
                    colors=OutlinedTextFieldDefaults.colors(
                        focusedTextColor=Color.White,unfocusedTextColor=Color.White))
                if(CommerceSession.user==null){
                    Button(onClick=onSignIn,modifier=Modifier.fillMaxWidth(),
                        colors=ButtonDefaults.buttonColors(containerColor=Color.White,
                            contentColor=Color.Black)){Text(tr("Sign in to redeem"))}
                }else{
                    Button(enabled=valid&&!busy,onClick={
                        scope.launch{
                            busy=true;error=null
                            try{
                                redeemed=auth.redeemGift(code)
                                code=""
                            }catch(e:CancellationException){throw e}
                            catch(e:Exception){
                                error=when(NativeCommerceAuth.diagnostic(e)){
                                    "GIFT_ALREADY_REDEEMED"->tr("Already redeemed")
                                    "GIFT_RATE_LIMITED"->tr("Too many attempts")
                                    "GIFT_INVALID"->tr("Invalid or expired code")
                                    else->tr("Please try again")
                                }
                            }finally{busy=false}
                        }
                    },modifier=Modifier.fillMaxWidth(),
                        colors=ButtonDefaults.buttonColors(containerColor=Color.White,
                            contentColor=Color.Black)){
                        Text(tr("Redeem"))
                    }
                }
                if(error!=null)Text(error.orEmpty(),color=Color(0xFFFFB9B9),fontSize=13.sp)
            }else{
                Icon(Icons.Outlined.CheckCircle,null,tint=Color(0xFFB8DCC0),
                    modifier=Modifier.size(32.dp))
                Text(tr("Gift redeemed"),color=Color.White,fontSize=20.sp,
                    fontWeight=FontWeight.Bold)
                val benefit=redeemed?.optString("product")
                Text(when(benefit){
                    "analysis-credits"->tr("Credits added")
                    "ads-free"->tr("Ad-free access activated")
                    else->tr("Offline license activated")
                },color=Color(0xFFB8DCC0))
                Button(onClick=onAccount,modifier=Modifier.fillMaxWidth(),
                    colors=ButtonDefaults.buttonColors(containerColor=Color.White,
                        contentColor=Color.Black)){
                    Text(tr("View my account"))
                }
            }
            if(busy)LinearProgressIndicator(Modifier.fillMaxWidth())
        }
    }
}
