package com.ghostdeveloper.spdecode

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.time.Instant
import java.text.DateFormat
import java.util.Date
import java.util.Locale

private val midnight=Color.Black
private val sectionPanel=Color(0xFF202020)
private val sectionRaised=Color(0xFF303030)
private val accent=Color(0xFFB6D9C0)
private val foreground=Color(0xFFF7F7F7)
private val secondary=Color(0xFFABABAB)

internal object CommerceAccountWords {
    private val keys=listOf("My profile","Your purchases","API licenses","Account security",
        "Ad-free experience","Available credits","Purchase history","Active licenses",
        "No purchases yet","No active licenses","Linked account","Valid until",
        "Inactive","Active","Manage account","Billing","Change IP address",
        "Public IP updated","Save IP","Purchase details","Payment confirmed",
        "Pending payment","Refunded","No subscription","Renew access",
        "Explore plans","Continue with Google","30 days without ads",
        "Remove ads from this account","Show purchases","Your account","Account settings")
    private val es=listOf("Mi perfil","Mis compras","Licencias API","Seguridad de la cuenta",
        "Sin anuncios","Créditos disponibles","Historial de compras","Licencias activas",
        "Todavía no hay compras","No tienes licencias activas","Cuenta vinculada","Válido hasta",
        "Inactivo","Activo","Administrar cuenta","Facturación","Cambiar IP pública",
        "IP actualizada","Guardar IP","Detalles del pedido","Pago confirmado",
        "Pago pendiente","Reembolsado","Sin suscripción","Renovar acceso",
        "Explorar planes","Continuar con Google","30 días sin anuncios",
        "Eliminar anuncios de esta cuenta","Ver compras","Tu cuenta","Configuración de cuenta")
    private val others=mapOf(
        "pt" to "Meu perfil|Minhas compras|Licenças API|Segurança da conta|Sem anúncios|Créditos disponíveis|Histórico de compras|Licenças ativas|Ainda não há compras|Sem licenças ativas|Conta vinculada|Válido até|Inativo|Ativo|Gerenciar conta|Cobrança|Alterar IP público|IP atualizado|Salvar IP|Detalhes do pedido|Pagamento confirmado|Pagamento pendente|Reembolsado|Sem assinatura|Renovar acesso|Explorar planos|Continuar com Google|30 dias sem anúncios|Remover anúncios desta conta|Ver compras|Sua conta|Configurações da conta",
        "fr" to "Mon profil|Mes achats|Licences API|Sécurité du compte|Sans publicité|Crédits disponibles|Historique des achats|Licences actives|Aucun achat|Aucune licence active|Compte lié|Valable jusqu'au|Inactif|Actif|Gérer le compte|Facturation|Modifier l'IP publique|IP mise à jour|Enregistrer l'IP|Détails de la commande|Paiement confirmé|Paiement en attente|Remboursé|Aucun abonnement|Renouveler|Voir les offres|Continuer avec Google|30 jours sans publicité|Supprimer les publicités de ce compte|Voir les achats|Votre compte|Paramètres du compte",
        "de" to "Mein Profil|Meine Käufe|API-Lizenzen|Kontosicherheit|Werbefrei|Verfügbare Credits|Kaufverlauf|Aktive Lizenzen|Noch keine Käufe|Keine aktiven Lizenzen|Verknüpftes Konto|Gültig bis|Inaktiv|Aktiv|Konto verwalten|Abrechnung|Öffentliche IP ändern|IP aktualisiert|IP speichern|Bestelldetails|Zahlung bestätigt|Zahlung ausstehend|Erstattet|Kein Abonnement|Zugang verlängern|Tarife ansehen|Mit Google fortfahren|30 Tage werbefrei|Werbung für dieses Konto entfernen|Käufe ansehen|Dein Konto|Kontoeinstellungen",
        "it" to "Il mio profilo|I miei acquisti|Licenze API|Sicurezza account|Senza pubblicità|Crediti disponibili|Storico acquisti|Licenze attive|Nessun acquisto|Nessuna licenza attiva|Account collegato|Valido fino al|Inattivo|Attivo|Gestisci account|Fatturazione|Cambia IP pubblico|IP aggiornato|Salva IP|Dettagli ordine|Pagamento confermato|Pagamento in sospeso|Rimborsato|Nessun abbonamento|Rinnova accesso|Esplora piani|Continua con Google|30 giorni senza annunci|Rimuovi annunci da questo account|Vedi acquisti|Il tuo account|Impostazioni account",
        "ru" to "Мой профиль|Мои покупки|Лицензии API|Безопасность аккаунта|Без рекламы|Доступные кредиты|История покупок|Активные лицензии|Покупок пока нет|Нет активных лицензий|Привязанный аккаунт|Действует до|Неактивно|Активно|Управление аккаунтом|Оплата|Изменить публичный IP|IP обновлён|Сохранить IP|Детали заказа|Оплата подтверждена|Ожидается оплата|Возвращено|Нет подписки|Продлить доступ|Посмотреть планы|Продолжить с Google|30 дней без рекламы|Убрать рекламу для аккаунта|Посмотреть покупки|Ваш аккаунт|Настройки аккаунта",
        "tr" to "Profilim|Satın almalarım|API lisansları|Hesap güvenliği|Reklamsız|Kullanılabilir krediler|Satın alma geçmişi|Etkin lisanslar|Henüz satın alma yok|Etkin lisans yok|Bağlı hesap|Geçerlilik|Pasif|Etkin|Hesabı yönet|Faturalama|Genel IP değiştir|IP güncellendi|IP kaydet|Sipariş detayları|Ödeme onaylandı|Ödeme bekleniyor|İade edildi|Abonelik yok|Erişimi yenile|Planlara göz at|Google ile devam et|30 gün reklamsız|Bu hesaptan reklamları kaldır|Satın almaları gör|Hesabın|Hesap ayarları",
        "ar" to "ملفي الشخصي|مشترياتي|تراخيص API|أمان الحساب|بدون إعلانات|الرصيد المتاح|سجل المشتريات|التراخيص النشطة|لا توجد مشتريات|لا توجد تراخيص نشطة|حساب مرتبط|صالح حتى|غير نشط|نشط|إدارة الحساب|الفوترة|تغيير IP العام|تم تحديث IP|حفظ IP|تفاصيل الطلب|تم تأكيد الدفع|بانتظار الدفع|تم الاسترداد|لا اشتراك|تجديد الوصول|تصفح الخطط|المتابعة مع Google|30 يومًا بلا إعلانات|إزالة الإعلانات من الحساب|عرض المشتريات|حسابك|إعدادات الحساب",
        "fa" to "نمایه من|خریدهای من|مجوزهای API|امنیت حساب|بدون تبلیغات|اعتبار موجود|سابقه خرید|مجوزهای فعال|هنوز خریدی نیست|مجوز فعالی نیست|حساب متصل|معتبر تا|غیرفعال|فعال|مدیریت حساب|صورتحساب|تغییر IP عمومی|IP به‌روز شد|ذخیره IP|جزئیات سفارش|پرداخت تأیید شد|در انتظار پرداخت|بازپرداخت شد|بدون اشتراک|تمدید دسترسی|مشاهده طرح‌ها|ادامه با Google|۳۰ روز بدون تبلیغات|حذف تبلیغات این حساب|نمایش خریدها|حساب شما|تنظیمات حساب",
        "hi" to "मेरी प्रोफ़ाइल|मेरी खरीदारी|API लाइसेंस|खाता सुरक्षा|विज्ञापन मुक्त|उपलब्ध क्रेडिट|खरीदारी इतिहास|सक्रिय लाइसेंस|अभी कोई खरीदारी नहीं|कोई सक्रिय लाइसेंस नहीं|जुड़ा खाता|मान्य तिथि|निष्क्रिय|सक्रिय|खाता प्रबंधित करें|बिलिंग|पब्लिक IP बदलें|IP अपडेट हुआ|IP सहेजें|ऑर्डर विवरण|भुगतान पुष्टि हुई|भुगतान लंबित|धनवापसी|कोई सदस्यता नहीं|एक्सेस नवीनीकृत करें|प्लान देखें|Google से जारी रखें|30 दिन बिना विज्ञापन|इस खाते के विज्ञापन हटाएँ|खरीदारी देखें|आपका खाता|खाता सेटिंग",
        "ja" to "マイプロフィール|購入履歴|APIライセンス|アカウントの安全性|広告なし|利用可能なクレジット|購入履歴|有効なライセンス|購入履歴はありません|有効なライセンスはありません|連携済みアカウント|有効期限|無効|有効|アカウント管理|請求|公開IPを変更|IPを更新しました|IPを保存|注文詳細|支払い完了|支払い待ち|返金済み|購読なし|利用を更新|プランを見る|Googleで続行|30日間広告なし|このアカウントの広告を削除|購入履歴を見る|アカウント|アカウント設定",
        "id" to "Profil saya|Pembelian saya|Lisensi API|Keamanan akun|Tanpa iklan|Kredit tersedia|Riwayat pembelian|Lisensi aktif|Belum ada pembelian|Tidak ada lisensi aktif|Akun terhubung|Berlaku hingga|Tidak aktif|Aktif|Kelola akun|Tagihan|Ubah IP publik|IP diperbarui|Simpan IP|Rincian pesanan|Pembayaran dikonfirmasi|Pembayaran tertunda|Dikembalikan|Tanpa langganan|Perpanjang akses|Lihat paket|Lanjutkan dengan Google|30 hari tanpa iklan|Hapus iklan untuk akun ini|Lihat pembelian|Akun Anda|Pengaturan akun",
        "vi" to "Hồ sơ của tôi|Đơn đã mua|Giấy phép API|Bảo mật tài khoản|Không quảng cáo|Tín dụng khả dụng|Lịch sử mua|Giấy phép đang hoạt động|Chưa có đơn mua|Không có giấy phép hoạt động|Tài khoản liên kết|Có hạn đến|Không hoạt động|Hoạt động|Quản lý tài khoản|Thanh toán|Đổi IP công khai|Đã cập nhật IP|Lưu IP|Chi tiết đơn hàng|Thanh toán thành công|Đang chờ thanh toán|Đã hoàn tiền|Chưa có gói|Gia hạn|Xem các gói|Tiếp tục với Google|30 ngày không quảng cáo|Xóa quảng cáo cho tài khoản này|Xem đơn mua|Tài khoản của bạn|Cài đặt tài khoản"
    ).mapValues{it.value.split("|")}
    fun get(language:String,key:String):String{
        val i=keys.indexOf(key)
        if(i<0)return key
        val locale=language.lowercase(Locale.ROOT)
        return when(locale){
            "es"->es[i]
            "en"->key
            "in"->others["id"]?.getOrNull(i)?:key
            else->others[locale]?.getOrNull(i)?:key
        }
    }
}

private fun friendlyDate(value:String,language:String):String{
    val date=runCatching{Date.from(Instant.parse(value))}.getOrNull()?:return "—"
    return DateFormat.getDateInstance(DateFormat.MEDIUM,Locale.forLanguageTag(language)).format(date)
}
private fun formatMoney(quote:JSONObject?):String{
    if(quote==null)return "—"
    val cents=quote.optInt("total",-1)
    if(cents<0)return "—"
    val currency=quote.optString("currency","USD")
    return String.format(Locale.US,"%.2f %s",cents/100.0,currency)
}
private fun items(snapshot:JSONObject?,key:String):List<JSONObject>{
    val arr=snapshot?.optJSONArray(key)?:return emptyList()
    return (0 until minOf(arr.length(),100)).mapNotNull{arr.optJSONObject(it)}
}
private fun activeLicenses(snapshot:JSONObject?,kind:String):List<JSONObject> =
    items(snapshot,"entitlements").filter{
        it.optString("product_id")==kind && it.optString("status")=="active" &&
        (it.isNull("expires_at")||it.optString("expires_at").isBlank()||
            runCatching{Instant.parse(it.optString("expires_at")).toEpochMilli()}
                .getOrDefault(0L)>System.currentTimeMillis())
    }

@Composable
private fun SectionCard(content:@Composable ColumnScope.()->Unit){
    Column(Modifier.fillMaxWidth().background(sectionPanel,RoundedCornerShape(22.dp))
        .padding(19.dp),verticalArrangement=Arrangement.spacedBy(14.dp),content=content)
}

@Composable
private fun SectionButton(title:String,description:String,icon:ImageVector,onClick:()->Unit){
    Row(Modifier.fillMaxWidth().background(sectionPanel,RoundedCornerShape(19.dp))
        .clickable(onClick=onClick).padding(horizontal=17.dp,vertical=17.dp),
        verticalAlignment=Alignment.CenterVertically,
        horizontalArrangement=Arrangement.spacedBy(14.dp)){
        Box(Modifier.size(44.dp).background(sectionRaised,RoundedCornerShape(14.dp)),
            contentAlignment=Alignment.Center){Icon(icon,null,tint=foreground)}
        Column(Modifier.weight(1f),verticalArrangement=Arrangement.spacedBy(4.dp)){
            Text(title,color=foreground,fontWeight=FontWeight.SemiBold,fontSize=16.sp)
            Text(description,color=secondary,fontSize=12.sp,maxLines=2)
        }
        Icon(Icons.Outlined.ChevronRight,null,tint=secondary)
    }
}
@Composable
private fun NumberPanel(title:String,value:String,icon:ImageVector){
    Column(Modifier.fillMaxWidth().background(sectionPanel,RoundedCornerShape(18.dp))
        .padding(16.dp),verticalArrangement=Arrangement.spacedBy(8.dp)){
        Icon(icon,null,tint=accent,modifier=Modifier.size(22.dp))
        Text(value,color=foreground,fontSize=25.sp,fontWeight=FontWeight.Bold)
        Text(title,color=secondary,fontSize=12.sp)
    }
}

@Composable
internal fun CommerceAccountHome(language:String,user:CommerceIdentity?,
    snapshot:JSONObject?,onSignIn:()->Unit,onEdit:()->Unit,onSignOut:()->Unit,
    onNavigate:(String)->Unit){
    val tr:(String)->String={CommerceAccountWords.get(language,it)}
    Text(tr("My profile"),color=foreground,fontSize=28.sp,fontWeight=FontWeight.Bold)
    CommerceAccountHero(language,user,onSignIn,onEdit,onSignOut)
    if(user==null)return
    val credit=snapshot?.optJSONObject("credits")?.optInt("available",0)?:0
    Row(horizontalArrangement=Arrangement.spacedBy(10.dp)){
        Box(Modifier.weight(1f)){NumberPanel(tr("Available credits"),credit.toString(),Icons.Outlined.Toll)}
        Box(Modifier.weight(1f)){NumberPanel(tr("Purchase history"),items(snapshot,"orders").size.toString(),Icons.Outlined.ReceiptLong)}
    }
    Text(tr("Manage account"),color=foreground,fontSize=18.sp,fontWeight=FontWeight.Bold)
    SectionButton(tr("Your purchases"),
        items(snapshot,"orders").size.toString(),Icons.Outlined.ReceiptLong){onNavigate("orders")}
    SectionButton(tr("API licenses"),
        activeLicenses(snapshot,"api-ip").size.toString(),Icons.Outlined.Dns){onNavigate("api")}
    SectionButton(tr("Ad-free experience"),
        if(CommerceSession.adFreeActive)tr("Active") else tr("Inactive"),
        Icons.Outlined.VerifiedUser){onNavigate("ad-free")}
    SectionButton(tr("Account security"),tr("Linked account"),
        Icons.Outlined.Shield){onNavigate("security")}
    SectionButton(CommerceI18n.translate(language,"Soporte técnico","Technical support"),
        CommerceI18n.translate(language,"Tus conversaciones","Your conversations"),
        Icons.Outlined.SupportAgent){onNavigate("support")}
    SectionButton(CommerceI18n.translate(language,"Eliminar cuenta","Delete account"),
        CommerceI18n.translate(language,"Privacidad y datos de la cuenta","Privacy and account data"),
        Icons.Outlined.DeleteForever){onNavigate("delete-account")}
}

@Composable
internal fun CommerceOrdersPage(language:String,snapshot:JSONObject?){
    val tr:(String)->String={CommerceAccountWords.get(language,it)}
    Text(tr("Your purchases"),fontSize=28.sp,fontWeight=FontWeight.Bold,color=foreground)
    val orders=items(snapshot,"orders")
    if(orders.isEmpty())SectionCard {
        Icon(Icons.Outlined.ReceiptLong,null,tint=accent,modifier=Modifier.size(30.dp))
        Text(tr("No purchases yet"),color=foreground,fontSize=16.sp)
    }
    orders.forEach{order->
        SectionCard {
            val id=order.optString("product_id")
            val title=when(id){
                "ads-free"->tr("Ad-free experience")
                "api-ip"->tr("API licenses")
                "analysis-credits"->tr("Available credits")
                else->"SP-DECODE Offline"
            }
            Row(verticalAlignment=Alignment.CenterVertically){
                Icon(Icons.Outlined.ReceiptLong,null,tint=accent)
                Spacer(Modifier.width(12.dp))
                Text(title,modifier=Modifier.weight(1f),color=foreground,
                    fontSize=17.sp,fontWeight=FontWeight.SemiBold)
                Text(formatMoney(order.optJSONObject("quote")),color=foreground)
            }
            val status=when(order.optString("status")){
                "paid"->tr("Payment confirmed")
                "pending","created"->tr("Pending payment")
                "refunded","disputed"->tr("Refunded")
                else->tr("Inactive")
            }
            Text(status,color=if(order.optString("status")=="paid")accent else secondary,
                fontSize=13.sp)
            Text(friendlyDate(order.optString("created_at"),language),color=secondary,fontSize=12.sp)
        }
    }
}

@Composable
internal fun CommerceApiPage(language:String,snapshot:JSONObject?,
    onUpdateIp:suspend (String,String)->JSONObject,onUpdated:(JSONObject)->Unit){
    val tr:(String)->String={CommerceAccountWords.get(language,it)}
    Text(tr("API licenses"),color=foreground,fontSize=28.sp,fontWeight=FontWeight.Bold)
    val licenses=activeLicenses(snapshot,"api-ip")
    if(licenses.isEmpty()) SectionCard {
        Icon(Icons.Outlined.Dns,null,tint=accent,modifier=Modifier.size(30.dp))
        Text(tr("No active licenses"),color=foreground)
    }
    licenses.forEach {item ->
        key(item.optString("id")){
            var address by remember(item.optString("id")) {
                mutableStateOf(item.optString("allowed_ip").takeUnless{it=="null"}.orEmpty())
            }
            var saving by remember {mutableStateOf(false)}
            var feedback by remember {mutableStateOf<String?>(null)}
            val scope=rememberCoroutineScope()
            SectionCard{
                Row(verticalAlignment=Alignment.CenterVertically){
                    Icon(Icons.Outlined.Key,null,tint=accent)
                    Spacer(Modifier.width(9.dp))
                    Text(tr("Active"),color=accent,fontWeight=FontWeight.SemiBold)
                }
                Text(item.optString("token_prefix").takeIf{it.isNotBlank()&&it!="null"}?:"API",
                    color=foreground,fontSize=19.sp,fontWeight=FontWeight.Bold)
                val expiration=item.optString("expires_at")
                if(expiration.isNotBlank()&&expiration!="null")
                    Text(tr("Valid until")+": "+friendlyDate(expiration,language),
                        color=secondary,fontSize=12.sp)
                OutlinedTextField(address,{address=it.take(45)},singleLine=true,
                    modifier=Modifier.fillMaxWidth(),
                    label={Text(tr("Change IP address"))},
                    colors=OutlinedTextFieldDefaults.colors(focusedTextColor=foreground,
                        unfocusedTextColor=foreground))
                Button(enabled=!saving&&CommercialServerIp.isPublicLiteral(address),
                    modifier=Modifier.fillMaxWidth(),onClick={
                        scope.launch{
                            saving=true;feedback=null
                            try{
                                onUpdated(onUpdateIp(item.optString("id"),address))
                                feedback=tr("Public IP updated")
                            }catch(_:Exception){
                                feedback=CommerceI18n.translate(language,
                                    "No se pudo actualizar la IP.","Unable to update IP.")
                            }finally{saving=false}
                        }
                    },colors=ButtonDefaults.buttonColors(containerColor=foreground,
                        contentColor=midnight)){
                    Text(tr("Save IP"))
                }
                if(feedback!=null)Text(feedback.orEmpty(),color=accent,fontSize=12.sp)
            }
        }
    }
}

@Composable
internal fun CommerceSecurityPage(language:String,user:CommerceIdentity?,
    hasPassword:Boolean,onEdit:()->Unit,onPassword:()->Unit,onSignOut:()->Unit){
    val tr:(String)->String={CommerceAccountWords.get(language,it)}
    Text(tr("Account security"),fontSize=28.sp,fontWeight=FontWeight.Bold,color=foreground)
    SectionCard {
        Row(verticalAlignment=Alignment.CenterVertically){
            Icon(Icons.Outlined.VerifiedUser,null,tint=accent)
            Spacer(Modifier.width(10.dp))
            Text(tr("Linked account"),color=foreground,fontSize=17.sp,
                fontWeight=FontWeight.Bold)
        }
        Text(CommerceProfileText.get(language,"Google account"),color=foreground)
        if(user!=null)Text(user.email,color=secondary)
        Text(CommerceI18n.translate(language,"Autenticación con Google",
            "Google authentication"),color=accent,fontSize=12.sp)
    }
    SectionButton(if(hasPassword)
            CommerceSecurityText.get(language,"Change password")
        else CommerceSecurityText.get(language,"Add password"),
        CommerceSecurityText.get(language,"Email sign-in"),
        Icons.Outlined.Lock,onPassword)
    CommerceDeviceAccountSettings(language)
    SectionButton(CommerceProfileText.get(language,"Edit profile"),
        tr("Manage account"),Icons.Outlined.Edit,onEdit)
    OutlinedButton(onClick=onSignOut,modifier=Modifier.fillMaxWidth()){
        Icon(Icons.Outlined.Logout,null)
        Spacer(Modifier.width(9.dp))
        Text(CommerceI18n.translate(language,"Cerrar sesión","Sign out"))
    }
}

@Composable
internal fun CommerceAdFreePage(language:String,onExplore:()->Unit){
    val tr:(String)->String={CommerceAccountWords.get(language,it)}
    Text(tr("Ad-free experience"),color=foreground,fontSize=28.sp,fontWeight=FontWeight.Bold)
    SectionCard {
        Box(Modifier.fillMaxWidth(),contentAlignment=Alignment.Center){
            Icon(Icons.Outlined.Shield,null,tint=accent,modifier=Modifier.size(65.dp))
        }
        Text(if(CommerceSession.adFreeActive)tr("Active") else tr("No subscription"),
            color=foreground,fontSize=21.sp,fontWeight=FontWeight.Bold)
        if(CommerceSession.adFreeActive){
            Text(tr("Valid until")+": "+
                friendlyDate(Instant.ofEpochMilli(CommerceSession.adsExpiry).toString(),language),
                color=accent,fontSize=14.sp)
        }else{
            Text(tr("30 days without ads"),color=secondary)
        }
    }
    Button(onClick=onExplore,modifier=Modifier.fillMaxWidth(),
        colors=ButtonDefaults.buttonColors(containerColor=foreground,contentColor=midnight)){
        Text(if(CommerceSession.adFreeActive)tr("Renew access") else tr("Explore plans"))
    }
}
