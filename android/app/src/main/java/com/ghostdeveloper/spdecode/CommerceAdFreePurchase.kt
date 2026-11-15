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
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.util.Locale

private val silver=Color(0xFFF8F8F8)
private val pale=Color(0xFFADB4B0)
private val shell=Color(0xFF222222)
private val ivy=Color(0xFFB7DBBE)

internal object StorefrontLabels {
    private val words=mapOf(
        "es" to ("Desactivado por el momento" to "Comprar"),
        "en" to ("Temporarily disabled" to "Buy"),
        "pt" to ("Desativado por enquanto" to "Comprar"),
        "fr" to ("Désactivé pour le moment" to "Acheter"),
        "de" to ("Derzeit deaktiviert" to "Kaufen"),
        "it" to ("Disattivato per il momento" to "Acquista"),
        "ru" to ("Временно отключено" to "Купить"),
        "tr" to ("Şimdilik devre dışı" to "Satın al"),
        "ar" to ("معطّل مؤقتًا" to "شراء"),
        "fa" to ("فعلاً غیرفعال" to "خرید"),
        "hi" to ("फ़िलहाल निष्क्रिय" to "खरीदें"),
        "ja" to ("現在無効" to "購入"),
        "id" to ("Dinonaktifkan sementara" to "Beli"),
        "vi" to ("Tạm thời bị vô hiệu hóa" to "Mua")
    )
    private fun labels(language:String)=words[language.substringBefore('-').let{if(it=="in")"id" else it}]?:words.getValue("en")
    fun disabled(language:String)=labels(language).first
    fun buy(language:String)=labels(language).second
}

internal object CommercePaymentText {
    private val keys=listOf("Select payment method","Billing country","Calculate total",
        "Total","Taxes","Continue to payment","Payment service unavailable",
        "Sign in to continue","Payment pending","Payment confirmed",
        "Your ad-free access is active","Complete purchase","Choose a provider",
        "Couldn't complete your request","USD","Ad-free for 30 days","Check purchase")
    private val es=listOf("Método de pago","País de facturación","Consultar total",
        "Total","Impuestos","Continuar al pago","Pago no disponible",
        "Inicia sesión para continuar","Pago pendiente","Pago confirmado",
        "Tu acceso sin anuncios está activo","Finalizar compra","Selecciona un proveedor",
        "No se pudo completar la solicitud","USD","30 días sin anuncios","Verificar compra")
    private val others=mapOf(
        "pt" to "Método de pagamento|País de cobrança|Calcular total|Total|Impostos|Continuar para pagamento|Pagamento indisponível|Entre para continuar|Pagamento pendente|Pagamento confirmado|Seu acesso sem anúncios está ativo|Finalizar compra|Escolha um provedor|Não foi possível concluir a solicitação|USD|30 dias sem anúncios|Verificar compra",
        "fr" to "Mode de paiement|Pays de facturation|Calculer le total|Total|Taxes|Procéder au paiement|Paiement indisponible|Connectez-vous pour continuer|Paiement en attente|Paiement confirmé|Votre accès sans publicité est actif|Finaliser l'achat|Choisir un fournisseur|Impossible de terminer la demande|USD|30 jours sans publicité|Vérifier l'achat",
        "de" to "Zahlungsmethode|Rechnungsland|Gesamtbetrag berechnen|Gesamt|Steuern|Zur Zahlung|Zahlung nicht verfügbar|Zum Fortfahren anmelden|Zahlung ausstehend|Zahlung bestätigt|Dein werbefreier Zugang ist aktiv|Kauf abschließen|Anbieter wählen|Anfrage konnte nicht abgeschlossen werden|USD|30 Tage ohne Werbung|Kauf prüfen",
        "it" to "Metodo di pagamento|Paese di fatturazione|Calcola totale|Totale|Imposte|Procedi al pagamento|Pagamento non disponibile|Accedi per continuare|Pagamento in attesa|Pagamento confermato|Accesso senza pubblicità attivo|Completa acquisto|Scegli il provider|Impossibile completare la richiesta|USD|30 giorni senza annunci|Verifica acquisto",
        "ru" to "Способ оплаты|Страна оплаты|Рассчитать сумму|Итого|Налоги|Перейти к оплате|Оплата недоступна|Войдите для продолжения|Ожидание оплаты|Оплата подтверждена|Режим без рекламы активен|Оформить покупку|Выберите провайдера|Не удалось выполнить запрос|USD|30 дней без рекламы|Проверить покупку",
        "tr" to "Ödeme yöntemi|Fatura ülkesi|Toplamı hesapla|Toplam|Vergiler|Ödemeye devam et|Ödeme kullanılamıyor|Devam etmek için giriş yap|Ödeme bekliyor|Ödeme onaylandı|Reklamsız erişimin etkin|Satın almayı tamamla|Sağlayıcı seç|İstek tamamlanamadı|USD|30 gün reklamsız|Satın almayı kontrol et",
        "ar" to "طريقة الدفع|بلد الفاتورة|حساب المجموع|المجموع|الضرائب|متابعة الدفع|الدفع غير متاح|سجل الدخول للمتابعة|الدفع قيد الانتظار|تم الدفع|وضع بلا إعلانات نشط|إكمال الشراء|اختر مزودا|تعذر إكمال الطلب|USD|30 يومًا بلا إعلانات|تحقق من الشراء",
        "fa" to "روش پرداخت|کشور صورتحساب|محاسبه کل|جمع|مالیات|ادامه پرداخت|پرداخت در دسترس نیست|برای ادامه وارد شوید|در انتظار پرداخت|پرداخت تأیید شد|دسترسی بدون تبلیغات فعال است|تکمیل خرید|انتخاب ارائه‌دهنده|درخواست انجام نشد|USD|۳۰ روز بدون تبلیغات|بررسی خرید",
        "hi" to "भुगतान विधि|बिलिंग देश|कुल की गणना|कुल|कर|भुगतान करें|भुगतान उपलब्ध नहीं|जारी रखने के लिए लॉग इन करें|भुगतान लंबित|भुगतान पुष्टि|विज्ञापन-मुक्त एक्सेस सक्रिय है|खरीद पूरी करें|प्रदाता चुनें|अनुरोध पूरा नहीं हुआ|USD|30 दिन बिना विज्ञापन|खरीद सत्यापित करें",
        "ja" to "支払い方法|請求先の国|合計を計算|合計|税金|支払いへ進む|支払い不可|ログインして続行|支払い待ち|支払い確認済み|広告なしが有効です|購入を完了|決済方法を選択|処理できませんでした|USD|30日間広告なし|購入を確認",
        "id" to "Metode pembayaran|Negara penagihan|Hitung total|Total|Pajak|Lanjutkan pembayaran|Pembayaran tidak tersedia|Masuk untuk melanjutkan|Pembayaran tertunda|Pembayaran dikonfirmasi|Akses tanpa iklan aktif|Selesaikan pembelian|Pilih penyedia|Permintaan gagal|USD|30 hari tanpa iklan|Periksa pembelian",
        "vi" to "Phương thức thanh toán|Quốc gia thanh toán|Tính tổng|Tổng|Thuế|Tiếp tục thanh toán|Thanh toán không khả dụng|Đăng nhập để tiếp tục|Đang chờ thanh toán|Đã xác nhận thanh toán|Đã bật không quảng cáo|Hoàn tất mua hàng|Chọn nhà cung cấp|Không thể hoàn tất yêu cầu|USD|30 ngày không quảng cáo|Kiểm tra đơn mua"
    ).mapValues{it.value.split("|")}
    fun get(lang:String,key:String):String {
        val index=keys.indexOf(key)
        if(index<0)return key
        return when(lang.lowercase(Locale.ROOT)){
            "es"->es[index]
            "in"->others["id"]?.getOrNull(index)?:key
            else->others[lang.lowercase(Locale.ROOT)]?.getOrNull(index)?:key
        }
    }
}

@Composable
internal fun CommerceAdFreePurchase(language:String,offer:StoreAdFreeOffer?,
    auth:NativeCommerceAuth,onSignIn:()->Unit,onOpenCheckout:(String)->Unit,
    onReloadCatalog:()->Unit,apiOffer:StoreApiOffer?=null,apiVersion:Int=0,allowedIp:String="",publicSalesOpen:Boolean=false){
    val tr:(String)->String={CommercePaymentText.get(language,it)}
    val scope=rememberCoroutineScope()
    val identity=CommerceSession.user
    val isApi=apiOffer!=null
    val product=if(isApi)"api-ip" else "ads-free"
    val term=apiOffer?.planId?:"base"
    val version=if(isApi)apiVersion else offer?.version?:0
    val methods=apiOffer?.providers?:offer?.providers.orEmpty()
    val prices=(apiOffer?.prices?:offer?.prices.orEmpty()).filterKeys{currency->
        methods.any{it!="mercadopago"||currency=="MXN"}
    }
    var currency by remember(prices,methods){mutableStateOf(prices.keys.firstOrNull { code->methods.any{it!="mercadopago"||code=="MXN"} }?:prices.keys.firstOrNull().orEmpty())}
    val availableMethods=methods.filter{it!="mercadopago"||currency=="MXN"}
    var provider by remember(availableMethods){mutableStateOf(availableMethods.firstOrNull().orEmpty())}
    var region by remember{mutableStateOf("")}
    var accepted by remember(product,term,version,currency,provider){mutableStateOf(false)}
    var country by remember{mutableStateOf(
        Locale.getDefault().country.takeIf{it.matches(Regex("[A-Za-z]{2}"))}
            ?.uppercase(Locale.ROOT)?:"MX")}
    var countryMenu by remember{mutableStateOf(false)}
    val countryCodes=listOf("MX","US","CA","CO","PE","AR","BR","CL","ES","FR",
        "DE","IT","GB","PT","TR","IN","ID","JP","AU","NZ")
    var quote by remember(product,term,version,currency,provider,country,region,allowedIp){mutableStateOf<JSONObject?>(null)}
    var requestKey by remember(product,term,version,currency,provider,country,region,allowedIp){mutableStateOf(java.util.UUID.randomUUID().toString())}
    var busy by remember{mutableStateOf(false)}
    var notice by remember{mutableStateOf<String?>(null)}
    val saleEnabled=publicSalesOpen && !BuildConfig.SPDECODE_PLAY_UPDATES && (apiOffer?.available?:offer?.available?:false) && availableMethods.isNotEmpty() && version>0
    Column(verticalArrangement=Arrangement.spacedBy(16.dp)){
        if(!isApi)Text(CommerceI18n.translate(language,"Sin anuncios","Ad-free"),
            color=silver,fontSize=29.sp,fontWeight=FontWeight.Bold)
        if(!isApi)Column(Modifier.fillMaxWidth().background(shell,RoundedCornerShape(24.dp))
            .padding(22.dp),horizontalAlignment=Alignment.CenterHorizontally,
            verticalArrangement=Arrangement.spacedBy(12.dp)){
            AdFreeSymbol(modifier=Modifier.size(65.dp))
            Text(tr("Ad-free for 30 days"),color=silver,fontSize=21.sp,
                fontWeight=FontWeight.Bold)
            if(CommerceSession.adFreeActive){
                Text(tr("Your ad-free access is active"),color=ivy,fontSize=14.sp)
                if(CommerceSession.adsExpiry>System.currentTimeMillis()){
                    val expiry=java.text.DateFormat.getDateInstance(java.text.DateFormat.MEDIUM,
                        Locale.forLanguageTag(language)).format(java.util.Date(CommerceSession.adsExpiry))
                    Text(CommerceI18n.translate(language,"Válido hasta ","Active until ")+expiry,
                        color=pale,fontSize=12.sp)
                }
            }else if(saleEnabled){
                Text(prices[currency]?.let{String.format(Locale.US,"%.2f %s",it/100.0,currency)}
                    ?:tr("Payment service unavailable"),
                    color=silver,fontSize=26.sp,fontWeight=FontWeight.Bold)
            }
        }
        if(!saleEnabled){
            Text(StorefrontLabels.disabled(language),color=pale,fontSize=14.sp)
        }else if(identity==null){
            Button(onClick=onSignIn,modifier=Modifier.fillMaxWidth(),
                colors=ButtonDefaults.buttonColors(containerColor=silver,contentColor=Color.Black)){
                Text(tr("Sign in to continue"))
            }
        }else if(saleEnabled){
            Row(Modifier.fillMaxWidth(),horizontalArrangement=Arrangement.spacedBy(8.dp)){
                prices.keys.forEach{code-> FilterChip(selected=currency==code,onClick={currency=code},label={Text(code)},enabled=!busy) }
            }
            Text(tr("Select payment method"),color=silver,fontSize=17.sp,fontWeight=FontWeight.SemiBold)
            availableMethods.forEach{id->
                Row(Modifier.fillMaxWidth().background(if(provider==id)Color(0xFF303D34)else shell,
                    RoundedCornerShape(15.dp)).clickable{
                        provider=id;quote=null;notice=null
                    }.padding(15.dp),verticalAlignment=Alignment.CenterVertically){
                    Icon(if(provider==id)Icons.Outlined.CheckCircle else Icons.Outlined.RadioButtonUnchecked,
                        null,tint=if(provider==id)ivy else pale)
                    Spacer(Modifier.width(12.dp))
                    Text(when(id){"stripe"->"Stripe";"paypal"->"PayPal";"mercadopago"->"Mercado Pago";else->id},
                        color=silver,fontSize=16.sp)
                }
            }
            Text(tr("Billing country"),color=silver,fontSize=15.sp,
                fontWeight=FontWeight.Medium)
            Box(Modifier.fillMaxWidth()){
                OutlinedButton(modifier=Modifier.fillMaxWidth(),
                    onClick={countryMenu=true}){
                    Text(Locale("",country).getDisplayCountry(
                        Locale.forLanguageTag(language)).ifBlank{country},
                        modifier=Modifier.weight(1f),color=silver)
                    Icon(Icons.Outlined.ArrowDropDown,null,tint=silver)
                }
                DropdownMenu(expanded=countryMenu,onDismissRequest={countryMenu=false}){
                    countryCodes.forEach{code->
                        DropdownMenuItem(
                            text={Text(Locale("",code).getDisplayCountry(
                                Locale.forLanguageTag(language)))},
                            onClick={country=code;countryMenu=false;quote=null;notice=null})
                    }
                }
            }
            OutlinedTextField(value=region,onValueChange={region=it.uppercase(Locale.ROOT).filter{ch->ch in 'A'..'Z'||ch in '0'..'9'||ch=='-'}.take(12)},singleLine=true,
                label={Text(CommerceI18n.translate(language,"Estado / región (opcional)","State / region (optional)"))},modifier=Modifier.fillMaxWidth(),enabled=!busy)
            if(quote==null){
                Button(onClick={
                    scope.launch{
                        busy=true;notice=null
                        try{quote=auth.quoteProduct(product,term,provider,currency,country,region,allowedIp)}
                        catch(_:Exception){notice=tr("Couldn't complete your request")}
                        finally{busy=false}
                    }
                },enabled=!busy&&saleEnabled&&provider.isNotEmpty()&&Regex("[A-Z]{2}").matches(country),
                    modifier=Modifier.fillMaxWidth(),
                    colors=ButtonDefaults.buttonColors(containerColor=silver,contentColor=Color.Black)){
                    Text(tr("Calculate total"))
                }
            }else{
                Column(Modifier.fillMaxWidth().background(shell,RoundedCornerShape(20.dp))
                    .padding(18.dp),verticalArrangement=Arrangement.spacedBy(10.dp)){
                    val total=quote!!.optInt("total",0)
                    val tax=quote!!.optInt("tax",0)
                    Text(tr("Taxes")+": "+String.format(Locale.US,"%.2f %s",tax/100.0,currency),
                        color=pale,fontSize=14.sp)
                    Text(tr("Total")+": "+String.format(Locale.US,"%.2f %s",total/100.0,currency),
                        color=silver,fontSize=22.sp,fontWeight=FontWeight.Bold)
                    Row(verticalAlignment=Alignment.CenterVertically){
                        Checkbox(checked=accepted,onCheckedChange={accepted=it},enabled=!busy)
                        Text(CommerceI18n.translate(language,"Acepto los términos de compra","I accept the purchase terms"),color=silver,fontSize=13.sp)
                    }
                    Button(onClick={
                        scope.launch {
                            busy=true;notice=null
                            try {
                                val quotedVersion=quote!!.optInt("version",0)
                                if(quotedVersion!=version)throw IllegalStateException("PRICE_CHANGED")
                                val url=auth.checkoutProduct(product,term,provider,currency,country,region,allowedIp,quotedVersion,requestKey)
                                CommerceSession.beginCheckout()
                                onOpenCheckout(url)
                                notice=tr("Payment pending")
                            }catch(_:Exception){
                                notice=tr("Couldn't complete your request")
                            }finally{busy=false}
                        }
                    },modifier=Modifier.fillMaxWidth(),enabled=!busy&&saleEnabled&&accepted&&total>=100,
                        colors=ButtonDefaults.buttonColors(containerColor=silver,contentColor=Color.Black)){
                        Text(StorefrontLabels.buy(language))
                    }
                }
            }
        }
        OutlinedButton(modifier=Modifier.fillMaxWidth(),enabled=!busy,
            onClick={notice=null;quote=null;onReloadCatalog()}){
            Icon(Icons.Outlined.Refresh,null,tint=silver)
            Spacer(Modifier.width(9.dp))
            Text(CommerceI18n.translate(language,"Actualizar precios","Refresh prices"),
                color=silver)
        }
        if(!isApi && identity!=null && (CommerceSession.checkoutPending||CommerceSession.adFreeActive)){
            OutlinedButton(modifier=Modifier.fillMaxWidth(),enabled=!busy,
                onClick={
                    scope.launch{
                        busy=true
                        try{
                            auth.account()
                            notice=if(CommerceSession.adFreeActive)tr("Payment confirmed")
                                else tr("Payment pending")
                        }catch(_:Exception){notice=tr("Couldn't complete your request")}
                        finally{busy=false}
                    }
                }){
                Icon(Icons.Outlined.Refresh,null,tint=silver)
                Spacer(Modifier.width(9.dp))
                Text(tr("Check purchase"),color=silver)
            }
        }
        if(busy)LinearProgressIndicator(Modifier.fillMaxWidth(),color=ivy)
        if(notice!=null)Text(notice.orEmpty(),color=ivy,fontSize=13.sp)
    }
}
