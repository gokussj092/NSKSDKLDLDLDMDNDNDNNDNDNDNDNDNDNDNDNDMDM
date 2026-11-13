package com.ghostdeveloper.spdecode

import android.content.res.Configuration
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.platform.LocalContext
import kotlinx.coroutines.launch
import org.json.JSONObject
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import java.net.Inet6Address
import java.net.InetAddress

// Android-only storefront and account UI. All transactions, sessions, balances
// and price authority remain on the server. No WebView, browser or local API key.
private val black=Color(0xFF000000)
private val panel=Color(0xFF242424)
private val raised=Color(0xFF303030)
private val white=Color(0xFFF7F7F7)
private val muted=Color(0xFFB0B0B0)
private val stroke=Color(0xFF444444)
private val good=Color(0xFFB8DCC0)

// The app recreates on language changes; this helper is safe in click handlers.
private fun local(es:String,en:String):String =
    if(java.util.Locale.getDefault().language=="es")es else en

internal object CommercialServerIp {
    /** UI preflight only; the Node server separately checks the authoritative IP. */
    fun isPublicLiteral(input:String):Boolean {
        val value=input.trim()
        if(value.isEmpty()||value!=input||value.length>45||
            value.any{it.isWhitespace()||it=='%'||it=='@'||it=='/'})return false
        if(value.contains(':')){
            if(!Regex("[0-9a-fA-F:.]+").matches(value))return false
            val addr=runCatching { InetAddress.getByName(value) }.getOrNull()
            if(addr !is Inet6Address)return false
            val bytes=addr.address.map{it.toInt() and 255}
            val first=bytes[0]
            if(first !in 0x20..0x3f)return false
            // The documentation-only 2001:db8::/32 is not public.
            if(bytes[0]==0x20 && bytes[1]==0x01 &&
               bytes[2]==0x0d && bytes[3]==0xb8)return false
            return !addr.isAnyLocalAddress && !addr.isLoopbackAddress &&
                !addr.isLinkLocalAddress && !addr.isSiteLocalAddress
        }
        val pieces=value.split('.')
        if(pieces.size!=4||pieces.any{it.isEmpty()||it.length>3||
                (it.length>1&&it[0]=='0')||it.any{c->c !in '0'..'9'}})return false
        val a=pieces.map{it.toIntOrNull()?:return false}
        if(a.any{it !in 0..255})return false
        val (x,y,z)=a
        return when {
            x==0 || x==10 || x==127 || x>=224 ->false
            x==100 && y in 64..127 ->false
            x==169 && y==254 ->false
            x==172 && y in 16..31 ->false
            x==192 && (y==168 || (y==0&&z==0) ||
                (y==0&&z==2) || (y==88&&z==99)) ->false
            x==198 && ((y==18||y==19) || (y==51&&z==100)) ->false
            x==203 && y==0 && z==113 ->false
            else ->true
        }
    }
}

private data class CommercialLine(val key:String,val title:String,
    val priceCents:Int,val detail:String)

private data class CreditPack(val id:String,val credits:Int,val priceCents:Int,val available:Boolean)
private data class ApiTerm(val key:String,val days:Int,val priceCents:Int,val available:Boolean)
private fun usd(cents:Int):String = "$"+(cents/100)+"."+((cents%100).toString().padStart(2,'0'))

@Composable
private fun SlateCard(content:@Composable ColumnScope.()->Unit) {
    Column(Modifier.fillMaxWidth().background(panel,RoundedCornerShape(20.dp))
        .padding(17.dp),verticalArrangement=Arrangement.spacedBy(13.dp),content=content)
}
@Composable
private fun PrimaryAction(text:String,enabled:Boolean=true,onClick:()->Unit) {
    Button(onClick=onClick,enabled=enabled,modifier=Modifier.fillMaxWidth(),
        shape=RoundedCornerShape(18.dp),
        colors=ButtonDefaults.buttonColors(containerColor=white,contentColor=Color.Black,
            disabledContainerColor=raised,disabledContentColor=muted),
        contentPadding=PaddingValues(vertical=15.dp)) {
        Text(text,fontWeight=FontWeight.SemiBold)
    }
}
@Composable
private fun Note(text:String) {
    Row(verticalAlignment=Alignment.Top,horizontalArrangement=Arrangement.spacedBy(8.dp)){
        Icon(Icons.Outlined.Info,null,tint=muted,modifier=Modifier.size(17.dp))
        Text(text,color=muted,fontSize=12.sp,lineHeight=17.sp,
            modifier=Modifier.weight(1f))
    }
}
@Composable
private fun ProductTile(name:String,description:String,price:String,details:String,icon:@Composable ()->Unit,
    onClick:()->Unit){
    Column(Modifier.fillMaxWidth().background(panel,RoundedCornerShape(19.dp))
        .clickable(onClick=onClick).padding(18.dp),
        verticalArrangement=Arrangement.spacedBy(13.dp)){
        Row(verticalAlignment=Alignment.CenterVertically,
            horizontalArrangement=Arrangement.spacedBy(14.dp)){
            Box(Modifier.size(55.dp).background(raised,RoundedCornerShape(15.dp)),
                contentAlignment=Alignment.Center){icon()}
            Column(Modifier.weight(1f),verticalArrangement=Arrangement.spacedBy(3.dp)){
                Text(name,fontWeight=FontWeight.Bold,fontSize=17.sp,color=white)
                Text(description,color=muted,fontSize=12.sp,lineHeight=17.sp)
            }
            Icon(Icons.Outlined.ChevronRight,null,tint=white)
        }
        HorizontalDivider(color=stroke)
        Row(verticalAlignment=Alignment.CenterVertically,
            horizontalArrangement=Arrangement.SpaceBetween,
            modifier=Modifier.fillMaxWidth()){
            Text(price,color=white,fontWeight=FontWeight.SemiBold,fontSize=16.sp)
            Text(details,color=white,fontSize=12.sp)
        }
    }
}
@Composable
private fun SimpleFeature(title:String,subtitle:String?=null){
    Row(verticalAlignment=Alignment.Top,horizontalArrangement=Arrangement.spacedBy(11.dp)){
        Icon(Icons.Outlined.CheckCircle,null,tint=good,modifier=Modifier.size(19.dp))
        Column(verticalArrangement=Arrangement.spacedBy(3.dp)){
            Text(title,color=white,fontSize=14.sp)
            if(subtitle!=null)Text(subtitle,color=muted,fontSize=12.sp)
        }
    }
}

/**
 * Native, isolated UI pilot. Checkout and authentication are deliberately
 * unavailable until the server exposes approved product prices, a mobile-safe
 * session flow and verified payment callbacks.
 */
@Composable
internal fun NativeCommerceScreens(start:String,onExit:()->Unit,
    onLegalLink:(String)->Unit={},onCheckoutUrl:(String)->Unit={}) {
    val entryPage=start
    var page by rememberSaveable(start){mutableStateOf(entryPage)}
    var detail by rememberSaveable {mutableStateOf("home")}
    var pack by rememberSaveable {mutableIntStateOf(1)}
    var quantity by rememberSaveable {mutableIntStateOf(1)}
    var term by rememberSaveable {mutableIntStateOf(0)}
    var serverIp by rememberSaveable {mutableStateOf("")}
    var lines by remember {mutableStateOf<List<CommercialLine>>(emptyList())}
    var notice by remember {mutableStateOf<String?>(null)}
    val context=LocalContext.current
    val language=context.resources.configuration.locales[0].language
    // Capture the actual app-specific locale, not Locale.getDefault().
    // The app's independent language selector overrides Activity resources.
    val local:(String,String)->String={es,en->CommerceI18n.translate(language,es,en)}
    val auth=remember(context){NativeCommerceAuth(context)}
    val scope=rememberCoroutineScope()
    var signingIn by remember {mutableStateOf(false)}
    var email by remember {mutableStateOf("")}
    var emailPassword by remember {mutableStateOf("")}
    var acceptedPolicies by rememberSaveable {mutableStateOf(false)}
    var accountSnapshot by remember {mutableStateOf<JSONObject?>(null)}
    var ipEdit by rememberSaveable{mutableStateOf("")}
    LaunchedEffect(page){
        if(page in setOf("account","orders","api","security","ad-free","profile-edit","password","gift","delete-account"))
            accountSnapshot=auth.account()
    }
    var catalog by remember {mutableStateOf<NativeStoreCatalog?>(null)}
    var catalogLoaded by remember {mutableStateOf(false)}
    // Read new offers whenever the user enters the store; prices are server-owned.
    LaunchedEffect(page,detail){
        if(page=="store"||page=="ad-free"){
            catalogLoaded=false
            catalog=NativeStoreCatalog.load()
            catalogLoaded=true
        }
    }
    val creditPacks=catalog?.creditPacks.orEmpty().map {
        CreditPack(it.planId,it.credits,it.priceCents,it.available)
    }
    val apiTerms=catalog?.apiPlans.orEmpty().map {
        ApiTerm(it.planId,it.days,it.priceCents,it.available)
    }
    LaunchedEffect(creditPacks.size){if(pack !in creditPacks.indices)pack=0}
    LaunchedEffect(apiTerms.size){if(term !in apiTerms.indices)term=0}
    val creditSelection=creditPacks.getOrNull(pack)
    val apiSelection=apiTerms.getOrNull(term)
    fun back(){
        when {
            page=="profile-edit" -> if(start=="profile-edit")onExit() else page="account"
            page=="password" -> if(start=="password")onExit() else page="security"
            page=="email-login" -> page="login"
            page=="gift" -> if(start=="gift")onExit() else {page="store";detail="home"}
            page=="delete-account" -> if(start=="delete-account")onExit() else page="account"
            page in setOf("support","report") -> if(start==page)onExit() else page="account"
            page=="account" && start=="profile-edit" -> onExit()
            page in setOf("orders","api","security","ad-free") ->
                if(start==page)onExit() else page="account"
            page=="cart" -> {page="store";detail="home"}
            page=="store" && detail!="home" -> detail="home"
            page=="login" && start!="login" -> page="account"
            page!=entryPage -> page=entryPage
            else -> onExit()
        }
    }
    BackHandler{back()}
    Column(Modifier.fillMaxSize().background(black).safeDrawingPadding()){
        Row(Modifier.fillMaxWidth().padding(horizontal=12.dp,vertical=9.dp),
            verticalAlignment=Alignment.CenterVertically){
            IconButton(onClick={back()}){
                Icon(Icons.Outlined.ArrowBack,local("Volver","Back"),tint=white)
            }
            Column(Modifier.weight(1f)){
                Text("SP-DECODE",color=white,fontWeight=FontWeight.Bold,fontSize=21.sp)
                Text(when(page) {
                    "account" -> local("Mi cuenta","My account")
                    "profile-edit" -> CommerceProfileText.get(language,"Edit profile")
                    "orders" -> CommerceAccountWords.get(language,"Your purchases")
                    "api" -> CommerceAccountWords.get(language,"API licenses")
                    "security" -> CommerceAccountWords.get(language,"Account security")
                    "password" -> CommerceSecurityText.get(language,"Password")
                    "gift" -> CommerceGiftText.get(language,"Redeem gift code")
                    "email-login" -> local("Acceso con correo","Email sign in")
                    "support" -> local("Soporte técnico","Technical support")
                    "report" -> local("Reportar un error","Report an issue")
                    "delete-account" -> local("Eliminar cuenta","Delete account")
                    "ad-free" -> CommerceAccountWords.get(language,"Ad-free experience")
                    "login" -> local("Acceso seguro","Secure sign in")
                    "cart" -> local("Tu carrito","Your cart")
                    else -> local("Tienda","Store")
                },color=muted,fontSize=12.sp)
            }
            if(page=="store"){
                IconButton(onClick={page="cart"}) {
                    Icon(Icons.Outlined.ShoppingCart,local("Carrito","Cart"),tint=white)
                }
                if(lines.isNotEmpty())Text(lines.size.toString(),color=white,fontSize=12.sp)
            }
        }
        HorizontalDivider(color=Color(0xFF292929))
        val chatPage=page=="support"||page=="report"
        val bodyModifier=if(chatPage)
            Modifier.weight(1f).fillMaxWidth()
                .padding(horizontal=15.dp,vertical=10.dp)
        else
            Modifier.weight(1f).fillMaxWidth().verticalScroll(rememberScrollState())
                .padding(horizontal=17.dp,vertical=19.dp)
        Column(bodyModifier,verticalArrangement=Arrangement.spacedBy(17.dp)){
            if(NativeDeviceAccountGuard.enabled(context) &&
                !NativeDeviceAccountGuard.unlocked &&
                page in setOf("account","orders","api","security","ad-free","profile-edit","password","gift","delete-account","support","report"))
                CommerceAccountUnlockPage(language)
            else when(page){
                "store" -> when(detail){
                    "credits" -> {
                        Text(local("CRÉDITOS / ANÁLISIS APK","CREDITS / APK ANALYSIS"),
                            fontSize=11.sp,color=muted)
                        Text(local("Créditos de análisis","Analysis credits"),
                            color=white,fontSize=26.sp,fontWeight=FontWeight.Bold)
                        Text(local("Un crédito permite analizar una aplicación APK/APKS elegible. Los archivos VPN normales no consumen estos créditos.",
                            "One credit covers one eligible APK/APKS analysis. Normal VPN file decoding does not use these credits."),
                            color=muted,fontSize=13.sp)
                        SlateCard{
                            Text(local("Selecciona un paquete","Choose a pack"),
                                color=white,fontWeight=FontWeight.Bold)
                            creditPacks.forEachIndexed{index,item->
                                Row(Modifier.fillMaxWidth().background(
                                        if(pack==index)Color(0xFF414141)else raised,
                                        RoundedCornerShape(12.dp))
                                    .clickable{pack=index}.padding(13.dp),
                                    verticalAlignment=Alignment.CenterVertically){
                                    Icon(if(pack==index)Icons.Outlined.CheckCircle
                                        else Icons.Outlined.RadioButtonUnchecked,null,
                                        tint=white,modifier=Modifier.size(20.dp))
                                    Spacer(Modifier.width(10.dp))
                                    Column(Modifier.weight(1f)){
                                        Text(item.credits.toString()+" "+local("créditos","credits"),
                                            fontWeight=FontWeight.SemiBold,color=white)
                                        val unit=creditPacks.firstOrNull{it.credits==1}?.priceCents
                                        if(item.credits>1 && unit!=null && item.priceCents<unit*item.credits)
                                            Text(local("Ahorra ","Save ")+
                                                ((100-item.priceCents*100/(unit*item.credits)).toString())+"%",
                                                color=good,fontSize=12.sp)
                                    }
                                    Text(usd(item.priceCents)+" USD",color=white)
                                }
                            }
                            if(creditPacks.isEmpty())Note(local("No disponible actualmente.","Currently unavailable."))
                            HorizontalDivider(color=stroke)
                            Row(verticalAlignment=Alignment.CenterVertically){
                                Column(Modifier.weight(1f)){
                                    Text(local("Paquetes","Packs"),color=white)
                                    Text(((creditSelection?.credits?:0)*quantity).toString()+" "+
                                        local("créditos totales","total credits"),
                                        color=muted,fontSize=12.sp)
                                }
                                IconButton(onClick={quantity=(quantity-1).coerceAtLeast(1)},
                                    enabled=quantity>1) {Icon(Icons.Outlined.Remove,null,tint=white)}
                                Text(quantity.toString(),color=white,fontWeight=FontWeight.Bold)
                                IconButton(onClick={quantity=(quantity+1).coerceAtMost(20)},
                                    enabled=quantity<20) {Icon(Icons.Outlined.Add,null,tint=white)}
                            }
                            Row(Modifier.fillMaxWidth(),
                                horizontalArrangement=Arrangement.SpaceBetween){
                                Text(local("Total","Total"),color=white,fontWeight=FontWeight.Bold)
                                Text(creditSelection?.let{usd(it.priceCents*quantity)+" USD"}?:"—",
                                    color=white,fontSize=20.sp,fontWeight=FontWeight.Bold)
                            }
                            PrimaryAction(local("Agregar al carrito","Add to cart"),enabled=creditSelection?.available==true){
                                val selected=creditSelection?:return@PrimaryAction
                                lines=lines.filterNot{it.key=="analysis-credits"}+
                                    CommercialLine("analysis-credits",
                                        (selected.credits*quantity).toString()+" "+
                                            local("créditos APK","APK credits"),
                                        selected.priceCents*quantity,"")
                                page="cart"
                            }
                            Spacer(Modifier.height(2.dp))
                        }
                    }
                    "api" -> {
                        Text("API / SP-DECODE",color=muted,fontSize=11.sp)
                        Text(local("API Comercial","Commercial API"),color=white,
                            fontSize=26.sp,fontWeight=FontWeight.Bold)
                        Text(local("Accede a los métodos de descifrado desde tu servidor usando una clave API y una IP pública autorizada.",
                            "Use decoding methods from your server with an API key bound to an authorized public IP."),
                            color=muted,fontSize=13.sp)
                        SlateCard{
                            Text(local("Servicios incluidos","Included services"),color=white,
                                fontWeight=FontWeight.Bold)
                            SimpleFeature(local("Descifrado de archivos","File decoding"))
                            SimpleFeature(local("Descifrado de textos","Text decoding"))
                            SimpleFeature(local("Métodos online","Online methods"))
                            SimpleFeature(local("Descifrado de catálogos","Catalog decoding"))
                            HorizontalDivider(color=stroke)
                            Row(verticalAlignment=Alignment.CenterVertically,
                                horizontalArrangement=Arrangement.spacedBy(9.dp)){
                                Icon(Icons.Outlined.Block,null,tint=muted)
                                Text(local("No incluye análisis de aplicaciones APK/APKS",
                                    "APK/APKS application analysis is not included"),
                                    color=muted,fontSize=13.sp,fontWeight=FontWeight.SemiBold)
                            }
                        }
                        SlateCard{
                            Text(local("Duración de la licencia","License duration"),
                                color=white,fontWeight=FontWeight.Bold)
                            apiTerms.forEachIndexed{index,item->
                                Row(Modifier.fillMaxWidth().background(
                                    if(term==index)Color(0xFF414141)else raised,
                                    RoundedCornerShape(12.dp)).clickable{term=index}
                                    .padding(13.dp),verticalAlignment=Alignment.CenterVertically){
                                    Icon(if(term==index)Icons.Outlined.CheckCircle
                                        else Icons.Outlined.RadioButtonUnchecked,null,
                                        tint=white,modifier=Modifier.size(20.dp))
                                    Spacer(Modifier.width(10.dp))
                                    Text(item.days.toString()+" "+local("días","days"),
                                        color=white,modifier=Modifier.weight(1f))
                                    Text(usd(item.priceCents)+" USD",color=white)
                                }
                            }
                            if(apiTerms.isEmpty())Note(local("No disponible actualmente.","Currently unavailable."))
                            HorizontalDivider(color=stroke)
                            Text(local("IP pública del servidor (opcional al comprar)",
                                "Public server IP (optional at purchase)"),color=white,fontWeight=FontWeight.Bold)
                            OutlinedTextField(
                                value=serverIp,
                                onValueChange={serverIp=it.take(45)},
                                singleLine=true,
                                label={Text(local("IPv4 o IPv6 pública","Public IPv4 or IPv6"))},
                                placeholder={Text("195.233.233.12")},
                                leadingIcon={Icon(Icons.Outlined.Dns,null)},
                                isError=serverIp.isNotBlank()&&!CommercialServerIp.isPublicLiteral(serverIp),
                                modifier=Modifier.fillMaxWidth().testTag("commerce_api_public_server_ip"),
                                colors=OutlinedTextFieldDefaults.colors(
                                    focusedTextColor=white,unfocusedTextColor=white,
                                    focusedBorderColor=white,unfocusedBorderColor=stroke,
                                    focusedLabelColor=white,unfocusedLabelColor=muted,
                                    cursorColor=white),
                            )
                            if(serverIp.isNotBlank()&&!CommercialServerIp.isPublicLiteral(serverIp))
                                Text(local("Introduce una IP pública válida; no se permiten IP privadas, locales ni dominios.",
                                    "Enter a valid public IP; private, local and domain values are not accepted."),
                                    color=Color(0xFFFFB9B9),fontSize=12.sp)
                            Note(local("Puedes comprar sin IP y configurarla después desde Mi cuenta. La clave no funcionará sin vincular una IP pública válida. Puedes cambiarla más adelante.",
                                "You may buy without an IP, then bind a public server IP from My account before the key can be used. You may change it later."))
                            PrimaryAction(local("Agregar API al carrito","Add API to cart"),
                                enabled=apiSelection?.available==true && (serverIp.isBlank()||CommercialServerIp.isPublicLiteral(serverIp))){
                                val chosen=apiSelection?:return@PrimaryAction
                                lines=lines.filterNot{it.key=="api-ip"}+
                                    CommercialLine("api-ip","API · "+chosen.days+" "+local("días","days"),
                                        chosen.priceCents,serverIp.trim())
                                page="cart"
                            }
                        }
                    }
                    "ads" -> {
                        CommerceAdFreePurchase(language,catalog?.adFree,auth,
                            onSignIn={page="login"},onOpenCheckout=onCheckoutUrl,
                            onReloadCatalog={
                                scope.launch{
                                    catalogLoaded=false
                                    catalog=NativeStoreCatalog.load()
                                    catalogLoaded=true
                                    accountSnapshot=auth.account()
                                }
                            })
                    }
                    else -> {
                        SlateCard{
                            Row(verticalAlignment=Alignment.Top){
                                Column(Modifier.weight(1f)){
                                    Text(local("SERVICIOS SP-DECODE","SP-DECODE SERVICES"),
                                        color=muted,fontSize=11.sp)
                                    Spacer(Modifier.height(8.dp))
                                    Text(local("Todo para tus proyectos.",
                                        "Everything for your projects."),
                                        color=white,fontSize=25.sp,fontWeight=FontWeight.Bold,
                                        lineHeight=29.sp)
                                    Spacer(Modifier.height(7.dp))
                                    Text(local("Créditos, API y una experiencia libre de anuncios.",
                                        "Credits, API and an ad-free experience."),
                                        color=muted,fontSize=13.sp)
                                }
                                Icon(Icons.Outlined.Storefront,null,
                                    modifier=Modifier.size(43.dp),tint=white)
                            }
                        }
                        if(!catalogLoaded)LinearProgressIndicator(
                            modifier=Modifier.fillMaxWidth(),color=good)
                        else if(catalog==null)Note(local(
                            "No se pudo cargar la tienda. Inténtalo de nuevo más tarde.",
                            "The store is unavailable. Please try again later."))
                        Text(local("Explorar productos","Browse products"),fontSize=19.sp,
                            fontWeight=FontWeight.Bold,color=white)
                        ProductTile(local("Créditos de análisis","Analysis credits"),
                            local("Análisis de APK/APKS y resultados técnicos",
                                "APK/APKS analysis and technical results"),
                            creditPacks.minOfOrNull{it.priceCents}?.let{usd(it)+" USD"}?:local("No disponible","Unavailable"),
                            local("Ver detalles","Details"),
                            {Icon(Icons.Outlined.Inventory2,null,tint=white,modifier=Modifier.size(29.dp))}){
                            detail="credits"
                        }
                        ProductTile(local("API Comercial","Commercial API"),
                            local("Archivos, textos, métodos online y catálogos",
                                "Files, text, online methods and catalogs"),
                            apiTerms.minOfOrNull{it.priceCents}?.let{usd(it)+" USD"}?:local("No disponible","Unavailable"),
                            local("Ver detalles","Details"),
                            {Icon(Icons.Outlined.Code,null,tint=white,modifier=Modifier.size(29.dp))}){
                            detail="api"
                        }
                        ProductTile(local("Quitar anuncios","Remove ads"),
                            local("Un mes completo sin publicidad","One month without ads"),
                            when {
                                CommerceSession.adFreeActive -> CommerceAccountWords.get(language,"Active")
                                catalog?.adFree!=null -> usd(catalog!!.adFree!!.priceCents)+" USD"
                                else -> local("No disponible","Unavailable")
                            },
                            local("Ver detalles","Details"),
                            {Icon(Icons.Outlined.Shield,null,tint=white,modifier=Modifier.size(29.dp))}){
                            detail="ads"
                        }
                        ProductTile(local("Canjear código de regalo","Redeem gift code"),
                            local("Una sorpresa te espera. Descúbrela al canjear tu código.",
                                "A surprise awaits. Redeem your code to discover it."),
                            local("Canjear","Redeem"),"",
                            {Icon(Icons.Outlined.CardGiftcard,null,tint=white,
                                modifier=Modifier.size(29.dp))}){
                            page="gift"
                        }
                        SlateCard{
                            Row(verticalAlignment=Alignment.CenterVertically){
                                Icon(Icons.Outlined.SupportAgent,null,tint=white)
                                Spacer(Modifier.width(11.dp))
                                Text(local("Soporte y facturación","Support & billing"),
                                    fontWeight=FontWeight.SemiBold,color=white)
                            }
                            Text(local("Gestiona tus compras y beneficios desde Mi cuenta.",
                                "Manage purchases and benefits in My account."),
                                color=muted,fontSize=13.sp)
                        }
                    }
                }
                "cart" -> {
                    Text(local("Resumen del pedido","Order summary"),color=white,
                        fontSize=25.sp,fontWeight=FontWeight.Bold)
                    SlateCard{
                        if(lines.isEmpty()){
                            Text(local("Todavía no agregaste productos.","Your cart is empty."),
                                color=muted)
                        }else lines.forEach{item->
                            Row(verticalAlignment=Alignment.CenterVertically){
                                Column(Modifier.weight(1f)){
                                    Text(item.title,color=white,fontWeight=FontWeight.SemiBold)
                                    if(item.detail.isNotEmpty())Text(
                                        local("IP autorizada: ","Authorized IP: ")+item.detail,
                                        color=muted,fontSize=12.sp)
                                    Text(usd(item.priceCents)+" USD",color=muted,fontSize=13.sp)
                                }
                                IconButton(onClick={lines=lines.filterNot{it.key==item.key}}){
                                    Icon(Icons.Outlined.Delete,
                                        local("Quitar","Remove"),tint=white)
                                }
                            }
                            HorizontalDivider(color=stroke)
                        }
                        val total=lines.sumOf{it.priceCents}
                        Row(Modifier.fillMaxWidth(),
                            horizontalArrangement=Arrangement.SpaceBetween){
                            Text(local("Subtotal","Subtotal"),
                                fontWeight=FontWeight.SemiBold,color=white)
                            Text(usd(total)+" USD",color=white,
                                fontWeight=FontWeight.Bold,fontSize=19.sp)
                        }
                        Spacer(Modifier.height(2.dp))
                    }
                }
                "account" -> {
                    CommerceAccountHome(language,CommerceSession.user,accountSnapshot,
                        onSignIn={page="login"},onEdit={page="profile-edit"},
                        onSignOut={
                            scope.launch {
                                runCatching {auth.signOut()}
                                accountSnapshot=null
                                page="login"
                            }
                        },onNavigate={page=it})
                }
                "orders" -> CommerceOrdersPage(language,accountSnapshot)
                "api" -> CommerceApiPage(language,accountSnapshot,
                    onUpdateIp={id,ip->auth.editApiIp(id,ip)},
                    onUpdated={
                        scope.launch{accountSnapshot=auth.account()}
                    })
                "security" -> CommerceSecurityPage(language,CommerceSession.user,
                    hasPassword=accountSnapshot?.optJSONObject("user")?.optBoolean("hasPassword")==true,
                    onEdit={page="profile-edit"},onPassword={page="password"},
                    onSignOut={
                        scope.launch{
                            runCatching{auth.signOut()}
                            accountSnapshot=null
                            page="login"
                        }
                    })
                "ad-free" -> CommerceAdFreePage(language,
                    onExplore={page="store";detail="ads"})
                "password" -> CommercePasswordPage(language,auth,CommerceSession.user,
                    hasPassword=accountSnapshot?.optJSONObject("user")?.optBoolean("hasPassword")==true,
                    onSaved={accountSnapshot=it;page="security"})
                "gift" -> CommerceGiftRedeemPage(language,auth,
                    onSignIn={page="login"},onAccount={page="account"})
                "support" -> CommerceSupportPage(language,auth,false,onSignIn={page="login"})
                "report" -> CommerceSupportPage(language,auth,true,onSignIn={page="login"})
                "delete-account" -> CommerceDeleteAccountPage(language,auth,
                    onDeleted={accountSnapshot=null;page="login"})
                "profile-edit" -> {
                    CommerceProfileEditor(language=language,auth=auth,
                        user=CommerceSession.user,onCancel={page="account"},
                        onSaved={updated->
                            accountSnapshot=updated
                            page="account"
                        })
                }
                "email-login" -> {
                    Text(local("Iniciar sesión con correo","Sign in with email"),
                        color=white,fontSize=27.sp,fontWeight=FontWeight.Bold)
                    SlateCard {
                        OutlinedTextField(email,{email=it.take(254)},
                            modifier=Modifier.fillMaxWidth(),singleLine=true,
                            label={Text(local("Correo electrónico","Email address"))},
                            colors=OutlinedTextFieldDefaults.colors(
                                focusedTextColor=white,unfocusedTextColor=white))
                        OutlinedTextField(emailPassword,{emailPassword=it.take(128)},
                            modifier=Modifier.fillMaxWidth(),singleLine=true,
                            visualTransformation=PasswordVisualTransformation(),
                            label={Text(local("Contraseña","Password"))},
                            colors=OutlinedTextFieldDefaults.colors(
                                focusedTextColor=white,unfocusedTextColor=white))
                        if(notice!=null)Note(notice.orEmpty())
                        if(NativeDeviceAccountGuard.enabled(context) &&
                           auth.sessionToken()!=null &&
                           NativeDeviceAccountGuard.supported(context)){
                            OutlinedButton(modifier=Modifier.fillMaxWidth(),onClick={
                                NativeDeviceAccountGuard.authenticate(context,
                                    local("Iniciar con huella o PIN","Sign in with fingerprint or PIN")){ok->
                                    if(ok)scope.launch{
                                        accountSnapshot=auth.account()
                                        if(accountSnapshot!=null)page="account"
                                        else notice=local("La sesión venció. Inicia con contraseña o Google.",
                                            "Session expired. Sign in with password or Google.")
                                    }
                                }
                            }){
                                Icon(Icons.Outlined.Fingerprint,null,tint=white)
                                Spacer(Modifier.width(8.dp))
                                Text(local("Acceso rápido con huella o PIN",
                                    "Quick sign in with fingerprint or PIN"),color=white)
                            }
                        }
                        PrimaryAction(local("Iniciar sesión","Sign in"),
                            enabled=!signingIn&&email.contains("@")&&emailPassword.isNotEmpty()){
                            scope.launch{
                                signingIn=true;notice=null
                                try {
                                    accountSnapshot=auth.signInWithEmail(email,emailPassword)
                                    emailPassword=""
                                    page="account"
                                }catch(e:kotlinx.coroutines.CancellationException){throw e}
                                catch(_:Exception){
                                    notice=local("Credenciales incorrectas o cuenta no disponible.",
                                        "Invalid credentials or account unavailable.")
                                }finally{signingIn=false}
                            }
                        }
                        if(signingIn)LinearProgressIndicator(Modifier.fillMaxWidth(),color=white)
                    }
                }
                "login" -> CommerceAuthLanding(language,acceptedPolicies,
                    signingIn,notice,
                    onAccepted={acceptedPolicies=it},onLegalLink=onLegalLink,
                    onGoogle={
                        if(!signingIn)scope.launch{
                            signingIn=true;notice=null
                            try{
                                accountSnapshot=auth.signInWithGoogle(acceptedPolicies)
                                page="account"
                            }catch(e:kotlinx.coroutines.CancellationException){throw e}
                            catch(e:Exception){
                                val code=NativeCommerceAuth.diagnostic(e)
                                if(code!="GOOGLE_SIGN_IN_CANCELLED")
                                    notice=local("No se pudo iniciar sesión. Verifica Google y tu conexión.",
                                        "Sign-in failed. Verify Google and your connection.")+
                                        " ("+code+")"
                            }finally{signingIn=false}
                        }
                    },onEmail={page="email-login"})
            }
        }
    }
}
