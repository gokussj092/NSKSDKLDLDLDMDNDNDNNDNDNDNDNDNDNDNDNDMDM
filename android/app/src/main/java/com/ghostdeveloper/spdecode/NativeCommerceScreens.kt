package com.ghostdeveloper.spdecode

import android.content.res.Configuration
import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
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

private data class CreditPack(val credits:Int,val priceCents:Int)
private val creditPacks=listOf(CreditPack(1,399),CreditPack(10,3290),CreditPack(100,23900))
private data class ApiTerm(val key:String,val days:Int,val priceCents:Int)
private val apiTerms=listOf(ApiTerm("1m",30,599),ApiTerm("3m",90,1549),ApiTerm("12m",360,4999))
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
private fun ProductTile(name:String,description:String,price:String,icon:@Composable ()->Unit,
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
            Text(local("Ver detalles","Details"),color=white,fontSize=12.sp)
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
internal fun NativeCommerceScreens(start:String,onExit:()->Unit) {
    var page by rememberSaveable(start){mutableStateOf(start)}
    var detail by rememberSaveable {mutableStateOf("home")}
    var pack by rememberSaveable {mutableIntStateOf(1)}
    var quantity by rememberSaveable {mutableIntStateOf(1)}
    var term by rememberSaveable {mutableIntStateOf(0)}
    var serverIp by rememberSaveable {mutableStateOf("")}
    var lines by remember {mutableStateOf<List<CommercialLine>>(emptyList())}
    var profileTab by rememberSaveable {mutableStateOf("overview")}
    var authTab by rememberSaveable {mutableStateOf("login")}
    var authMethod by rememberSaveable {mutableStateOf("choose")}
    var email by rememberSaveable {mutableStateOf("")}
    // Never serialize even an inactive password field to Android saved state.
    var password by remember {mutableStateOf("")}
    var notice by remember {mutableStateOf<String?>(null)}
    LaunchedEffect(page){if(page!="login")password=""}
    var securityDialog by remember {mutableStateOf(false)}
    fun back(){
        when {
            page=="cart" -> {page="store";detail="home"}
            page=="store" && detail!="home" -> detail="home"
            page=="login" && start!="login" -> page="account"
            page!=start -> page=start
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
        Column(Modifier.weight(1f).fillMaxWidth().verticalScroll(rememberScrollState())
            .padding(horizontal=17.dp,vertical=19.dp),
            verticalArrangement=Arrangement.spacedBy(17.dp)){
            when(page){
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
                                        if(item.credits>1)Text(
                                            local("Ahorra ","Save ")+
                                                ((100-(item.priceCents*100/(399*item.credits))).toString())+"%",
                                            color=good,fontSize=12.sp)
                                    }
                                    Text(usd(item.priceCents)+" USD",color=white)
                                }
                            }
                            HorizontalDivider(color=stroke)
                            Row(verticalAlignment=Alignment.CenterVertically){
                                Column(Modifier.weight(1f)){
                                    Text(local("Paquetes","Packs"),color=white)
                                    Text((creditPacks[pack].credits*quantity).toString()+" "+
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
                                Text(usd(creditPacks[pack].priceCents*quantity)+" USD",
                                    color=white,fontSize=20.sp,fontWeight=FontWeight.Bold)
                            }
                            PrimaryAction(local("Agregar al carrito","Add to cart")){
                                val selected=creditPacks[pack]
                                lines=lines.filterNot{it.key=="analysis-credits"}+
                                    CommercialLine("analysis-credits",
                                        (selected.credits*quantity).toString()+" "+
                                            local("créditos APK","APK credits"),
                                        selected.priceCents*quantity,"")
                                page="cart"
                            }
                            Note(local("Precios referenciales. El servidor determinará el precio definitivo al habilitar las compras.",
                                "Reference prices only. The server will determine prices when purchases are enabled."))
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
                            HorizontalDivider(color=stroke)
                            Text(local("IP pública del servidor (obligatoria)",
                                "Server public IP (required)"),color=white,fontWeight=FontWeight.Bold)
                            OutlinedTextField(
                                value=serverIp,
                                onValueChange={serverIp=it.take(45)},
                                singleLine=true,
                                label={Text(local("IPv4 o IPv6 pública","Public IPv4 or IPv6"))},
                                placeholder={Text("8.8.8.8")},
                                leadingIcon={Icon(Icons.Outlined.Dns,null)},
                                isError=serverIp.isNotBlank()&&!CommercialServerIp.isPublicLiteral(serverIp),
                                modifier=Modifier.fillMaxWidth().testTag("commerce_api_required_ip"),
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
                            Note(local("La clave funcionará únicamente desde esta IP. La API no se activará sin una IP válida. El servidor volverá a verificarla.",
                                "The API key will work only from this IP. Activation requires a valid IP, verified again by the server."))
                            PrimaryAction(local("Agregar API al carrito","Add API to cart"),
                                enabled=CommercialServerIp.isPublicLiteral(serverIp)){
                                val chosen=apiTerms[term]
                                lines=lines.filterNot{it.key=="api-ip"}+
                                    CommercialLine("api-ip","API · "+chosen.days+" "+local("días","days"),
                                        chosen.priceCents,serverIp)
                                page="cart"
                            }
                        }
                    }
                    "ads" -> {
                        Text(local("EXPERIENCIA / SP-DECODE","EXPERIENCE / SP-DECODE"),
                            color=muted,fontSize=11.sp)
                        Text(local("Quitar anuncios","Remove ads"),
                            color=white,fontSize=26.sp,fontWeight=FontWeight.Bold)
                        SlateCard{
                            Box(Modifier.fillMaxWidth(),contentAlignment=Alignment.Center) {
                                Icon(Icons.Outlined.Shield,null,tint=white,modifier=Modifier.size(65.dp))
                            }
                            Text("$1.00 USD",fontSize=30.sp,color=white,
                                fontWeight=FontWeight.Bold,modifier=Modifier.align(Alignment.CenterHorizontally))
                            Text(local("30 días sin publicidad dentro de la aplicación",
                                "30 days without ads inside the app"),
                                color=muted,textAlign=TextAlign.Center,fontSize=14.sp,
                                modifier=Modifier.fillMaxWidth())
                            HorizontalDivider(color=stroke)
                            SimpleFeature(local("No muestra anuncios intersticiales",
                                "No interstitial ads"))
                            SimpleFeature(local("Se aplica a tu cuenta activa",
                                "Applies to your active account"))
                            Note(local("No incluye créditos APK ni acceso API. No se renueva automáticamente en esta propuesta.",
                                "Does not include APK credits or API access. No automatic renewal in this proposal."))
                            PrimaryAction(local("Agregar por $1.00","Add for $1.00")){
                                lines=lines.filterNot{it.key=="ads-30d"}+
                                    CommercialLine("ads-30d",local("Sin anuncios · 30 días",
                                        "Ad-free · 30 days"),100,"")
                                page="cart"
                            }
                        }
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
                        Note(local("Tienda nativa en preparación. No se admiten pagos hasta conectar el catálogo, la cuenta y la verificación del servidor.",
                            "Native storefront in preparation. Payments remain disabled until catalog, account and server verification are connected."))
                        Text(local("Explorar productos","Browse products"),fontSize=19.sp,
                            fontWeight=FontWeight.Bold,color=white)
                        ProductTile(local("Créditos de análisis","Analysis credits"),
                            local("Análisis de APK/APKS y resultados técnicos",
                                "APK/APKS analysis and technical results"),
                            local("Desde $3.99 USD","From $3.99 USD"),
                            {Icon(Icons.Outlined.Inventory2,null,tint=white,modifier=Modifier.size(29.dp))}){
                            detail="credits"
                        }
                        ProductTile(local("API Comercial","Commercial API"),
                            local("Archivos, textos, métodos online y catálogos",
                                "Files, text, online methods and catalogs"),
                            local("Desde $5.99 USD","From $5.99 USD"),
                            {Icon(Icons.Outlined.Code,null,tint=white,modifier=Modifier.size(29.dp))}){
                            detail="api"
                        }
                        ProductTile(local("Quitar anuncios","Remove ads"),
                            local("Un mes completo sin publicidad","One month without ads"),
                            "$1.00 USD",
                            {Icon(Icons.Outlined.Shield,null,tint=white,modifier=Modifier.size(29.dp))}){
                            detail="ads"
                        }
                        SlateCard{
                            Row(verticalAlignment=Alignment.CenterVertically){
                                Icon(Icons.Outlined.SupportAgent,null,tint=white)
                                Spacer(Modifier.width(11.dp))
                                Text(local("Soporte y facturación","Support & billing"),
                                    fontWeight=FontWeight.SemiBold,color=white)
                            }
                            Text(local("Tu cuenta mostrará los pedidos, recibos, saldos, vigencias y claves cuando el servidor comercial esté habilitado.",
                                "Your account will display orders, receipts, balances, terms and keys when commerce services are enabled."),
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
                        Note(local("Los precios son referenciales; impuestos, descuentos, disponibilidad y pago final requieren cotización del servidor.",
                            "Reference prices only; taxes, discounts, availability and final payment require a server quote."))
                        PrimaryAction(local("Pago aún no habilitado","Checkout not enabled"),
                            enabled=false){}
                    }
                }
                "account" -> {
                    Text(local("Centro de cuenta","Account center"),color=white,
                        fontSize=25.sp,fontWeight=FontWeight.Bold)
                    SlateCard{
                        Row(verticalAlignment=Alignment.CenterVertically){
                            Box(Modifier.size(57.dp).background(raised,RoundedCornerShape(20.dp)),
                                contentAlignment=Alignment.Center){
                                Icon(Icons.Outlined.AccountCircle,null,tint=white,
                                    modifier=Modifier.size(36.dp))
                            }
                            Spacer(Modifier.width(12.dp))
                            Column(Modifier.weight(1f)){
                                Text(local("Invitado","Guest"),color=white,
                                    fontSize=17.sp,fontWeight=FontWeight.Bold)
                                Text(local("Sin sesión vinculada","No linked session"),
                                    color=muted,fontSize=12.sp)
                            }
                        }
                        PrimaryAction(local("Iniciar sesión","Sign in")){page="login"}
                    }
                    Row(Modifier.fillMaxWidth(),horizontalArrangement=Arrangement.spacedBy(4.dp)){
                        listOf("overview","orders","api","security").forEach{p->
                            Box(Modifier.weight(1f).background(
                                if(profileTab==p)Color(0xFF414141)else panel,
                                RoundedCornerShape(10.dp))
                                .clickable{profileTab=p}.padding(vertical=10.dp),
                                contentAlignment=Alignment.Center){
                                Text(when(p){
                                    "orders"->local("Compras","Orders")
                                    "api"->"API"
                                    "security"->local("Seguridad","Security")
                                    else->local("Resumen","Overview")
                                },color=white,fontSize=11.sp)
                            }
                        }
                    }
                    SlateCard{
                        when(profileTab){
                            "orders" -> {
                                Text(local("Historial de compras","Order history"),
                                    color=white,fontWeight=FontWeight.Bold)
                                Text(local("Facturas, pedidos y pagos confirmados aparecerán después de iniciar sesión.",
                                    "Invoices, orders and confirmed payments will appear after sign-in."),
                                    color=muted,fontSize=13.sp)
                            }
                            "api" -> {
                                Text(local("Mis claves API","My API keys"),color=white,
                                    fontWeight=FontWeight.Bold)
                                SimpleFeature(local("Ver límites y cuota","View limits and quota"))
                                SimpleFeature(local("Revisar IP autorizada","Review authorized IP"))
                                SimpleFeature(local("Rotar o revocar la clave","Rotate or revoke key"))
                                Note(local("La clave solamente se mostrará cuando exista una licencia verificada. Nunca se almacena como texto plano en la app.",
                                    "A key is shown only for a verified license. It is never stored in plain text in the app."))
                            }
                            "security" -> {
                                Text(local("Seguridad y credenciales","Security & credentials"),
                                    color=white,fontWeight=FontWeight.Bold)
                                SimpleFeature(local("Cuenta vinculada a Google","Google-linked account"))
                                OutlinedButton(
                                    modifier=Modifier.fillMaxWidth(),
                                    onClick={securityDialog=true}) {
                                    Text(local("Agregar o cambiar contraseña",
                                        "Add or change password"))
                                }
                                Note(local("El servidor todavía admite únicamente Google. Para ofrecer contraseñas habrá que verificar primero la identidad, añadir recuperación y evitar duplicar cuentas.",
                                    "The server currently supports Google only. Password support requires identity verification, recovery and safe account linking."))
                            }
                            else -> {
                                Text(local("Mis servicios","My services"),color=white,
                                    fontWeight=FontWeight.Bold)
                                SimpleFeature(local("Saldo de créditos APK","APK credit balance"),
                                    local("Disponible tras iniciar sesión","Available after sign-in"))
                                SimpleFeature(local("API comercial","Commercial API"),
                                    local("Licencias, vigencia e IP","Licenses, terms and IP"))
                                SimpleFeature(local("Quitar anuncios","Remove ads"),
                                    local("Estado y vencimiento","Status and expiration"))
                            }
                        }
                    }
                    OutlinedButton(modifier=Modifier.fillMaxWidth(),
                        onClick={page="store";detail="home"}){
                        Text(local("Abrir tienda","Open store"))
                    }
                }
                "login" -> {
                    Column(Modifier.fillMaxWidth().padding(top=14.dp,bottom=6.dp),
                        horizontalAlignment=Alignment.CenterHorizontally,
                        verticalArrangement=Arrangement.spacedBy(12.dp)){
                        Box(Modifier.size(76.dp).background(raised,RoundedCornerShape(22.dp)),
                            contentAlignment=Alignment.Center){
                            Icon(Icons.Outlined.Fingerprint,null,tint=white,
                                modifier=Modifier.size(48.dp))
                        }
                        Text("SP-DECODE",color=white,fontWeight=FontWeight.Bold,
                            fontSize=27.sp)
                        Text(local("Accede a tu cuenta desde la aplicación",
                            "Access your account inside the app"),
                            color=muted,fontSize=13.sp)
                    }
                    SlateCard{
                        Row(Modifier.fillMaxWidth(),
                            horizontalArrangement=Arrangement.spacedBy(8.dp)){
                            listOf("login","register").forEach{item->
                                Box(Modifier.weight(1f).background(
                                    if(authTab==item)Color(0xFF464646)else raised,
                                    RoundedCornerShape(14.dp))
                                    .clickable{authTab=item;notice=null}.padding(12.dp),
                                    contentAlignment=Alignment.Center){
                                    Text(if(item=="login")local("Iniciar sesión","Sign in")
                                        else local("Crear cuenta","Create account"),
                                        color=white,fontSize=14.sp)
                                }
                            }
                        }
                        Text(local("Elige cómo continuar","Choose how to continue"),
                            color=white,fontSize=18.sp,fontWeight=FontWeight.SemiBold)
                        OutlinedButton(onClick={
                            notice=local("Google se conectará mediante el selector seguro de Android y el servidor de cuentas. Todavía no hay una sesión real.",
                                "Google will use Android's secure account picker and the account server. No real session is active yet.")
                        },modifier=Modifier.fillMaxWidth()) {
                            Text("G",fontSize=19.sp,fontWeight=FontWeight.Bold)
                            Spacer(Modifier.width(12.dp))
                            Text(local("Continuar con Google","Continue with Google"))
                        }
                        Row(verticalAlignment=Alignment.CenterVertically){
                            HorizontalDivider(Modifier.weight(1f),color=stroke)
                            Text("   "+local("o por correo","or by email")+"   ",
                                color=muted,fontSize=12.sp)
                            HorizontalDivider(Modifier.weight(1f),color=stroke)
                        }
                        if(authMethod=="choose"){
                            OutlinedButton(onClick={authMethod="email"},
                                modifier=Modifier.fillMaxWidth()) {
                                Icon(Icons.Outlined.Email,null)
                                Spacer(Modifier.width(8.dp))
                                Text(local("Continuar con correo","Continue with email"))
                            }
                        }else{
                            OutlinedTextField(value=email,
                                onValueChange={email=it.take(254)},
                                label={Text(local("Correo electrónico","Email address"))},
                                singleLine=true,modifier=Modifier.fillMaxWidth(),
                                colors=OutlinedTextFieldDefaults.colors(
                                    focusedTextColor=white,unfocusedTextColor=white,
                                    focusedBorderColor=white,unfocusedBorderColor=stroke))
                            OutlinedTextField(value=password,
                                onValueChange={password=it.take(128)},
                                label={Text(local("Contraseña","Password"))},
                                singleLine=true,
                                visualTransformation=PasswordVisualTransformation(),
                                modifier=Modifier.fillMaxWidth(),
                                colors=OutlinedTextFieldDefaults.colors(
                                    focusedTextColor=white,unfocusedTextColor=white,
                                    focusedBorderColor=white,unfocusedBorderColor=stroke))
                            PrimaryAction(
                                if(authTab=="login")local("Iniciar sesión","Sign in")
                                else local("Crear cuenta","Create account"),
                                enabled=false){}
                            Note(local("El acceso con contraseña aún no está habilitado por el servidor. No se enviarán ni almacenarán estos datos.",
                                "Password sign-in is not yet enabled on the server. These values will not be sent or stored."))
                            TextButton(onClick={authMethod="choose";password="";notice=null}){
                                Text(local("Otros métodos de acceso","Other sign-in methods"))
                            }
                        }
                        if(notice!=null)Note(notice.orEmpty())
                    }
                    Text(local("El perfil permanece dentro de SP-DECODE. La identidad de Google requiere el flujo seguro proporcionado por Android; no se insertará un formulario falso de Google.",
                        "The profile stays inside SP-DECODE. Google identity uses Android's approved secure flow, not an embedded fake Google login form."),
                        color=muted,fontSize=12.sp)
                }
            }
        }
    }
    if(securityDialog)AlertDialog(
        onDismissRequest={securityDialog=false},
        title={Text(local("Contraseña de la cuenta","Account password"))},
        text={Text(local("Esta función requiere soporte seguro del servidor para añadir, cambiar y recuperar contraseñas sin perder la vinculación con Google. No se han cambiado las credenciales.",
            "This feature requires secure server support to add, change and recover passwords while keeping Google account linking intact. No credentials have been changed."))},
        confirmButton={TextButton(onClick={securityDialog=false}) {
            Text(local("Entendido","OK"))
        }},
        containerColor=panel,titleContentColor=white,textContentColor=muted)
}
