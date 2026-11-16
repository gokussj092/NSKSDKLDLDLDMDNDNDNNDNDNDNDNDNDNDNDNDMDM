package com.ghostdeveloper.spdecode

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.text.selection.SelectionContainer
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.AnnotatedString
import androidx.compose.ui.text.LinkAnnotation
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.text.withLink
import androidx.compose.ui.text.withStyle
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.text.DateFormat
import java.time.Instant
import java.util.Date
import java.util.Locale
import java.time.ZoneId
import java.util.UUID

// AMOLED exacto del tema global (SpDecodeAmoledTheme): nada de la paleta
// azul petróleo/cian antigua. Verde solo para el chip "Respondido".
private val supportText=Color(0xFFF7F7F7)
private val supportMuted=Color(0xFFABABAB)
private val supportPanel=Color(0xFF242424)
private val supportElevated=Color(0xFF2A2A2A)
private val supportBorder=Color(0xFF525252)
private val supportGreen=Color(0xFF38A36D)
private val supportAmber=Color(0xFFE0B563)
private val supportError=Color(0xFFFF8585)
private val supportOutgoing=Color(0xFF2A2A2A)
private val supportIncoming=Color(0xFF242424)

private fun parseIsoMs(input:String):Long? = runCatching{
    Instant.parse(input).toEpochMilli()
}.getOrNull()

private fun chatTime(input:String,full:Boolean=false):String = runCatching{
    val date=Date.from(Instant.parse(input))
    if(full)DateFormat.getDateTimeInstance(DateFormat.SHORT,DateFormat.SHORT).format(date)
    else DateFormat.getTimeInstance(DateFormat.SHORT).format(date)
}.getOrDefault("")

private fun chatDateKey(value:String):String=runCatching{
    Instant.parse(value).atZone(ZoneId.systemDefault()).toLocalDate().toString()
}.getOrDefault("")

private fun linkified(text:String):AnnotatedString{
    val builder=AnnotatedString.Builder()
    val regex=Regex("https?://[^\\s]+")
    var last=0
    regex.findAll(text).forEach{match->
        if(match.range.first>last)
            builder.append(text.substring(last,match.range.first))
        builder.withLink(LinkAnnotation.Url(match.value)){
            withStyle(SpanStyle(textDecoration=TextDecoration.Underline)){
                append(match.value)
            }
        }
        last=match.range.last+1
    }
    if(last<text.length)builder.append(text.substring(last))
    return builder.toAnnotatedString()
}

private data class PendingMsg(val key:String,val text:String,val atMs:Long,
    val failed:Boolean=false)

@Composable
private fun UnreadPill(count:Int){
    if(count<=0)return
    Box(Modifier.background(supportText,RoundedCornerShape(50))
        .padding(horizontal=8.dp,vertical=3.dp),
        contentAlignment=Alignment.Center){
        Text(if(count>99)"99+" else count.toString(),color=Color.Black,
            fontSize=11.sp,fontWeight=FontWeight.Bold,maxLines=1)
    }
}

@Composable
private fun ChatDayDivider(input:String,language:String){
    val label=runCatching{
        DateFormat.getDateInstance(DateFormat.MEDIUM,Locale.forLanguageTag(language))
            .format(Date.from(Instant.parse(input)))
    }.getOrDefault("")
    if(label.isNotEmpty()){
        Row(Modifier.fillMaxWidth().padding(horizontal=12.dp,vertical=16.dp),
            verticalAlignment=Alignment.CenterVertically,
            horizontalArrangement=Arrangement.spacedBy(12.dp)){
            HorizontalDivider(modifier=Modifier.weight(1f),color=supportBorder)
            Text(label,color=supportMuted,fontSize=11.sp,
                modifier=Modifier.background(supportPanel,RoundedCornerShape(50))
                    .border(.6.dp,supportBorder,RoundedCornerShape(50))
                    .padding(horizontal=13.dp,vertical=7.dp))
            HorizontalDivider(modifier=Modifier.weight(1f),color=supportBorder)
        }
    }
}

@Composable
private fun StatusChip(status:String,language:String){
    val label=when(status){
        "answered"->CommerceI18n.translate(language,"Respondido","Answered")
        "closed"->CommerceI18n.translate(language,"Cerrado","Closed")
        else->CommerceI18n.translate(language,"Pendiente","Pending")
    }
    val tint=when(status){
        "answered"->supportGreen
        "closed"->supportMuted
        else->supportAmber
    }
    val shape=RoundedCornerShape(50)
    Row(Modifier.background(supportPanel,shape).border(.8.dp,supportBorder,shape)
        .padding(horizontal=10.dp,vertical=7.dp),
        verticalAlignment=Alignment.CenterVertically,
        horizontalArrangement=Arrangement.spacedBy(6.dp)){
        Box(Modifier.size(6.dp).background(tint,CircleShape))
        Text(label,color=tint,fontWeight=FontWeight.SemiBold,fontSize=10.sp,
            maxLines=1)
    }
}

/** Burbuja de Yamada: avatar y nombre solo en la primera del grupo. */
@Composable
private fun AgentBubble(row:JSONObject,language:String,showAvatar:Boolean,
    showName:Boolean){
    val agent=row.optJSONObject("agent")
    val avatar=agent?.optString("avatar")?.takeIf{it.isNotBlank()}
    val shape=RoundedCornerShape(topStart=20.dp,topEnd=20.dp,
        bottomStart=6.dp,bottomEnd=20.dp)
    Row(Modifier.fillMaxWidth().padding(horizontal=10.dp,vertical=3.dp),
        verticalAlignment=Alignment.Bottom,
        horizontalArrangement=Arrangement.Start){
        Box(Modifier.width(40.dp).padding(end=8.dp,bottom=3.dp),
            contentAlignment=Alignment.Center){
            if(showAvatar)CommerceAvatar(avatar,Modifier.size(32.dp))
        }
        Column(Modifier.widthIn(min=90.dp,max=292.dp)
            .background(supportIncoming,shape)
            .border(.8.dp,supportBorder,shape)
            .padding(horizontal=14.dp,vertical=11.dp),
            verticalArrangement=Arrangement.spacedBy(7.dp)){
            if(showName)Text(
                CommerceI18n.translate(language,"Yamada","Yamada")+" · "+
                CommerceI18n.translate(language,"Asistente","Assistant"),
                color=supportText,fontSize=11.sp,fontWeight=FontWeight.SemiBold,
                maxLines=2)
            SelectionContainer{
                Text(linkified(row.optString("text")),color=supportText,
                    fontSize=14.sp,lineHeight=21.sp)
            }
            Text(chatTime(row.optString("at")),color=supportMuted,
                fontSize=10.sp,modifier=Modifier.align(Alignment.End))
        }
    }
}

@Composable
private fun OwnBubble(row:JSONObject,language:String,read:Boolean){
    val shape=RoundedCornerShape(topStart=20.dp,topEnd=20.dp,
        bottomStart=20.dp,bottomEnd=6.dp)
    Row(Modifier.fillMaxWidth().padding(horizontal=10.dp,vertical=3.dp),
        verticalAlignment=Alignment.Bottom,
        horizontalArrangement=Arrangement.End){
        Column(Modifier.widthIn(min=90.dp,max=292.dp)
            .background(supportOutgoing,shape)
            .border(.8.dp,supportBorder,shape)
            .padding(horizontal=14.dp,vertical=11.dp),
            verticalArrangement=Arrangement.spacedBy(7.dp)){
            SelectionContainer{
                Text(linkified(row.optString("text")),color=supportText,
                    fontSize=14.sp,lineHeight=21.sp)
            }
            Row(Modifier.align(Alignment.End),
                verticalAlignment=Alignment.CenterVertically,
                horizontalArrangement=Arrangement.spacedBy(4.dp)){
                Text(chatTime(row.optString("at")),color=supportMuted,fontSize=10.sp)
                if(read){
                    Icon(Icons.Outlined.DoneAll,null,tint=supportText,
                        modifier=Modifier.size(14.dp))
                    Text(CommerceI18n.translate(language,"Leído","Read"),
                        color=supportText,fontSize=10.sp)
                }else{
                    Icon(Icons.Outlined.Check,null,tint=supportMuted,
                        modifier=Modifier.size(14.dp))
                    Text(CommerceI18n.translate(language,"Enviado","Sent"),
                        color=supportMuted,fontSize=10.sp)
                }
            }
        }
    }
}

@Composable
private fun PendingBubble(pending:PendingMsg,language:String,onRetry:()->Unit){
    val shape=RoundedCornerShape(topStart=20.dp,topEnd=20.dp,
        bottomStart=20.dp,bottomEnd=6.dp)
    Row(Modifier.fillMaxWidth().padding(horizontal=10.dp,vertical=3.dp),
        verticalAlignment=Alignment.Bottom,
        horizontalArrangement=Arrangement.End){
        Column(Modifier.widthIn(min=90.dp,max=292.dp)
            .background(supportOutgoing,shape)
            .border(.8.dp,
                if(pending.failed)supportError else supportBorder,shape)
            .clickable(enabled=pending.failed){onRetry()}
            .padding(horizontal=14.dp,vertical=11.dp),
            verticalArrangement=Arrangement.spacedBy(7.dp)){
            Text(pending.text,color=supportText,fontSize=14.sp,lineHeight=21.sp)
            Row(Modifier.align(Alignment.End),
                verticalAlignment=Alignment.CenterVertically,
                horizontalArrangement=Arrangement.spacedBy(4.dp)){
                if(pending.failed){
                    Text(CommerceI18n.translate(language,
                        "No enviado — tocar para reintentar",
                        "Not sent — tap to retry"),
                        color=supportError,fontSize=10.sp)
                }else{
                    Icon(Icons.Outlined.Schedule,null,tint=supportMuted,
                        modifier=Modifier.size(13.dp))
                    Text(CommerceI18n.translate(language,"Enviando…","Sending…"),
                        color=supportMuted,fontSize=10.sp)
                }
            }
        }
    }
}

@Composable
private fun WelcomeBubble(language:String){
    val shape=RoundedCornerShape(topStart=20.dp,topEnd=20.dp,
        bottomStart=6.dp,bottomEnd=20.dp)
    Row(Modifier.fillMaxWidth().padding(horizontal=10.dp,vertical=3.dp),
        verticalAlignment=Alignment.Bottom,
        horizontalArrangement=Arrangement.Start){
        Box(Modifier.width(40.dp).padding(end=8.dp,bottom=3.dp),
            contentAlignment=Alignment.Center){
            CommerceAvatar(null,Modifier.size(32.dp))
        }
        Column(Modifier.widthIn(min=90.dp,max=292.dp)
            .background(supportIncoming,shape)
            .border(.8.dp,supportBorder,shape)
            .padding(horizontal=14.dp,vertical=11.dp),
            verticalArrangement=Arrangement.spacedBy(7.dp)){
            Text(CommerceI18n.translate(language,"Yamada","Yamada")+" · "+
                CommerceI18n.translate(language,"Asistente","Assistant"),
                color=supportText,fontSize=11.sp,fontWeight=FontWeight.SemiBold)
            Text(CommerceI18n.translate(language,
                "Hola, soy Yamada. Cuéntame qué problema tienes con la app y te ayudo.",
                "Hello, I'm Yamada. Tell me what problem you have with the app and I'll help you."),
                color=supportText,fontSize=14.sp,lineHeight=21.sp)
        }
    }
}

private sealed interface ChatItem{
    data class Day(val at:String):ChatItem
    data class Server(val row:JSONObject):ChatItem
    data class Local(val pending:PendingMsg):ChatItem
    data object Welcome:ChatItem
}

@Composable
internal fun CommerceSupportPage(language:String,auth:NativeCommerceAuth,
    report:Boolean,onSignIn:()->Unit,onExit:()->Unit){
    val t:(String,String)->String={es,en->CommerceI18n.translate(language,es,en)}
    val scope=rememberCoroutineScope()
    val category=if(report)"apk" else "technical"
    var inbox by remember{mutableStateOf<JSONObject?>(null)}
    var loadError by remember{mutableStateOf(false)}
    var loadTick by remember{mutableStateOf(0)}
    var activeId by remember{mutableStateOf("")}
    var newChat by remember{mutableStateOf(false)}
    var autoRouted by remember{mutableStateOf(false)}
    var text by remember{mutableStateOf("")}
    var busy by remember{mutableStateOf(false)}
    var error by remember{mutableStateOf<String?>(null)}
    var pending by remember{mutableStateOf(listOf<PendingMsg>())}
    var locallyRead by remember{mutableStateOf(setOf<String>())}
    var markedRead by remember{mutableStateOf(setOf<String>())}
    var suspensionUntilMs by remember{mutableStateOf<Long?>(null)}
    var suspensionUntilIso by remember{mutableStateOf<String?>(null)}
    var search by remember{mutableStateOf("")}
    var filter by remember{mutableStateOf("all")}
    var nowMs by remember{mutableStateOf(System.currentTimeMillis())}
    val scroll=rememberLazyListState()

    // Reloj para la cuenta atrás de la suspensión (se reactiva sola a cero).
    LaunchedEffect(Unit){
        while(isActive){
            nowMs=System.currentTimeMillis()
            delay(1_000)
        }
    }
    val suspended=suspensionUntilMs!=null && suspensionUntilMs!!>nowMs
    val suspendedUntilText=suspensionUntilIso?.let{chatTime(it)} ?: ""
    val remainingMs=(suspensionUntilMs?:nowMs)-nowMs
    val countdown="%02d:%02d".format((remainingMs/60_000).coerceAtLeast(0),
        ((remainingMs/1_000)%60).coerceAtLeast(0))

    suspend fun refreshInbox():JSONObject?{
        val fresh=auth.supportInbox()
        inbox=fresh
        loadError=false
        // El servidor es la autoridad del anti-spam: si el inbox trae el
        // campo suspension, su valor manda; si no lo trae (servidor antiguo),
        // se conserva el estado local fijado por el 429 SUPPORT_SUSPENDED.
        if(fresh.has("suspension")){
            val suspension=fresh.optJSONObject("suspension")
            val until=suspension?.optString("suspendedUntil")?.takeIf{it.isNotBlank()}
            suspensionUntilIso=until
            suspensionUntilMs=until?.let{parseIsoMs(it)}
        }
        return fresh
    }
    fun applySuspension(untilIso:String?){
        val until=untilIso?.takeIf{it.isNotBlank()}
        suspensionUntilIso=until
        suspensionUntilMs=until?.let{parseIsoMs(it)}
            ?: (System.currentTimeMillis()+3_600_000)
        if(until==null)suspensionUntilIso=
            Instant.ofEpochMilli(suspensionUntilMs!!).toString()
        scope.launch{runCatching{refreshInbox()}}
    }
    LaunchedEffect(loadTick){
        while(isActive){
            if(auth.sessionToken()!=null){
                runCatching{refreshInbox()}.onFailure{
                    if(inbox==null)loadError=true
                }
            }
            delay(12_000)
        }
    }

    val itemsJson=inbox?.optJSONArray("threads")
    val rawThreads=(0 until (itemsJson?.length()?:0))
        .mapNotNull{itemsJson?.optJSONObject(it)}
    fun threadUnread(thread:JSONObject):Int =
        if(thread.optString("id") in locallyRead)0
        else thread.optInt("unread",0)
    // Hilos con no leídos primero, luego por último mensaje.
    val threads=rawThreads.sortedWith(
        compareByDescending<JSONObject>{threadUnread(it)>0}
            .thenByDescending{parseIsoMs(it.optString("last_message_at"))?:0L})
    val unreadTotal=threads.sumOf{threadUnread(it)}
    val active=threads.firstOrNull{it.optString("id")==activeId}
    val entries=active?.optJSONArray("messages")
    val messages=(0 until(entries?.length()?:0)).mapNotNull{entries?.optJSONObject(it)}
    val staffReadAtMs=active?.optString("staffReadAt")
        ?.takeIf{it.isNotBlank()}?.let{parseIsoMs(it)}
    // Aviso anti-spam: el servidor solo emite la suspensión; como heurística
    // local se avisa también si hoy ya hay 3+ hilos con actividad.
    val todayKey=Instant.ofEpochMilli(nowMs).atZone(ZoneId.systemDefault())
        .toLocalDate().toString()
    val threadsToday=threads.count{
        chatDateKey(it.optString("last_message_at"))==todayKey
    }
    val showSpamWarning=suspended || threadsToday>=3

    // Entrada directa (D4, un solo ticket abierto): sin hilos -> chat nuevo
    // limpio; con hilo abierto -> se retoma automáticamente.
    LaunchedEffect(inbox,autoRouted){
        if(autoRouted||inbox==null)return@LaunchedEffect
        autoRouted=true
        val open=threads.firstOrNull{it.optString("status")!="closed"}
        if(open!=null)activeId=open.optString("id")
        else if(threads.isEmpty())newChat=true
    }
    // Al abrir un hilo: marcar leído en el servidor y limpiar el badge local.
    LaunchedEffect(activeId){
        val id=activeId
        if(id.isEmpty()||id in markedRead)return@LaunchedEffect
        markedRead=markedRead+id
        locallyRead=locallyRead+id
        scope.launch{runCatching{auth.markSupportThreadRead(id)}}
    }

    val displayItems: List<ChatItem> = remember(messages,pending,active,newChat){
        val out=mutableListOf<ChatItem>()
        if((active!=null || newChat) && messages.isEmpty() && pending.isEmpty())
            out += ChatItem.Welcome
        var previous:JSONObject?=null
        messages.forEach{message->
            if(previous==null ||
                chatDateKey(previous!!.optString("at"))!=
                    chatDateKey(message.optString("at")))
                out += ChatItem.Day(message.optString("at"))
            out += ChatItem.Server(message)
            previous=message
        }
        pending.forEach{out += ChatItem.Local(it)}
        out
    }
    val inChat=active!=null || newChat
    LaunchedEffect(activeId,newChat,displayItems.size){
        if(inChat && displayItems.isNotEmpty())
            scroll.animateScrollToItem(displayItems.lastIndex)
    }

    fun cannotSend():Boolean = busy||text.trim().isEmpty()||suspended
    fun sendNow(){
        val trimmed=text.trim()
        if(trimmed.isEmpty()||busy)return
        if(suspended){
            error=t("Soporte suspendido temporalmente. Podrás escribir de nuevo en %s.",
                "Support is temporarily suspended. You will be able to write again in %s.")
                .format(countdown)
            return
        }
        error=null
        if(newChat){
            // Sin formulario (D3): categoría fija y asunto provisional con los
            // primeros ~60 caracteres; el título real lo pone Yamada.
            busy=true
            scope.launch{
                try{
                    val subject=trimmed.take(60).trim()
                        .ifBlank{t("Soporte técnico","Technical support")}
                    val result=auth.openSupportThread(subject,category,trimmed)
                    val id=result.getString("id")
                    text=""
                    activeId=id
                    newChat=false
                    refreshInbox()
                }catch(e:NativeCommerceAuth.AuthFailure){
                    if(e.code=="SUPPORT_SUSPENDED")applySuspension(e.suspendedUntil)
                    else error=t("No se pudo crear la conversación",
                        "Could not create conversation")
                }catch(e:CancellationException){throw e}
                catch(_:Exception){
                    error=t("No se pudo crear la conversación",
                        "Could not create conversation")
                }finally{busy=false}
            }
        }else{
            val key=UUID.randomUUID().toString()
            val item=PendingMsg(key,trimmed,System.currentTimeMillis())
            pending=pending+item
            text=""
            scope.launch{
                try{
                    auth.sendSupportMessage(activeId,trimmed)
                    pending=pending.filterNot{it.key==key}
                    refreshInbox()
                }catch(e:NativeCommerceAuth.AuthFailure){
                    if(e.code=="SUPPORT_SUSPENDED"){
                        pending=pending.filterNot{it.key==key}
                        text=trimmed
                        applySuspension(e.suspendedUntil)
                    }else{
                        pending=pending.map{
                            if(it.key==key)it.copy(failed=true) else it
                        }
                    }
                }catch(e:CancellationException){throw e}
                catch(_:Exception){
                    pending=pending.map{
                        if(it.key==key)it.copy(failed=true) else it
                    }
                }
            }
        }
    }
    fun retryPending(item:PendingMsg){
        if(suspended){
            error=t("Soporte suspendido temporalmente. Podrás escribir de nuevo en %s.",
                "Support is temporarily suspended. You will be able to write again in %s.")
                .format(countdown)
            return
        }
        pending=pending.map{if(it.key==item.key)it.copy(failed=false) else it}
        scope.launch{
            try{
                auth.sendSupportMessage(activeId,item.text)
                pending=pending.filterNot{it.key==item.key}
                refreshInbox()
            }catch(e:NativeCommerceAuth.AuthFailure){
                if(e.code=="SUPPORT_SUSPENDED"){
                    pending=pending.filterNot{it.key==item.key}
                    text=item.text
                    applySuspension(e.suspendedUntil)
                }else{
                    pending=pending.map{
                        if(it.key==item.key)it.copy(failed=true) else it
                    }
                }
            }catch(e:CancellationException){throw e}
            catch(_:Exception){
                pending=pending.map{
                    if(it.key==item.key)it.copy(failed=true) else it
                }
            }
        }
    }
    fun navigateBack(){
        when{
            active!=null || newChat -> {
                if(newChat && threads.isEmpty()){onExit();return}
                activeId="";newChat=false;text="";error=null;pending=listOf()
            }
            else->onExit()
        }
    }
    BackHandler(enabled=active!=null||newChat){navigateBack()}

    Column(Modifier.fillMaxSize().background(Color.Black),
        verticalArrangement=Arrangement.spacedBy(8.dp)){
        if(auth.sessionToken()==null){
            Row(Modifier.fillMaxWidth().background(supportPanel)
                .padding(horizontal=8.dp,vertical=8.dp),
                verticalAlignment=Alignment.CenterVertically){
                IconButton(onClick=onExit){
                    Icon(Icons.Outlined.ArrowBack,t("Volver","Back"),tint=supportText)
                }
                Text(t("Centro de asistencia","Support center"),
                    color=supportText,fontSize=18.sp,fontWeight=FontWeight.SemiBold)
            }
            Column(Modifier.fillMaxWidth().padding(24.dp),
                horizontalAlignment=Alignment.CenterHorizontally,
                verticalArrangement=Arrangement.spacedBy(16.dp)){
                Icon(Icons.Outlined.SupportAgent,null,tint=supportText,
                    modifier=Modifier.size(52.dp))
                Text(t("Centro de asistencia","Support center"),
                    color=supportText,fontSize=22.sp,fontWeight=FontWeight.Bold)
                Button(onClick=onSignIn,
                    colors=ButtonDefaults.buttonColors(containerColor=supportText,
                        contentColor=Color.Black)){
                    Text(t("Iniciar sesión","Sign in"))
                }
            }
        }else if(inChat){
            val lastAgent=active?.let{thread->
                val list=thread.optJSONArray("messages")
                val rows=(0 until (list?.length()?:0))
                    .mapNotNull{list?.optJSONObject(it)}
                rows.lastOrNull{it.optString("sender")=="admin"}
                    ?.optJSONObject("agent")
            }
            val agentAvatar=lastAgent?.optString("avatar")?.takeIf{it.isNotBlank()}
            Row(Modifier.fillMaxWidth().background(supportPanel)
                .border(width=.6.dp,color=supportBorder)
                .padding(start=4.dp,end=12.dp,top=10.dp,bottom=10.dp),
                verticalAlignment=Alignment.CenterVertically,
                horizontalArrangement=Arrangement.spacedBy(9.dp)){
                IconButton(onClick={navigateBack()},modifier=Modifier.size(43.dp)){
                    Icon(Icons.Outlined.ArrowBack,
                        t("Conversaciones","Conversations"),tint=supportText)
                }
                CommerceAvatar(agentAvatar,Modifier.size(44.dp))
                Column(Modifier.weight(1f),
                    verticalArrangement=Arrangement.spacedBy(3.dp)){
                    Text(t("Yamada","Yamada"),color=supportText,fontSize=17.sp,
                        fontWeight=FontWeight.Bold,maxLines=1)
                    Text(t("Asistente","Assistant")+" · "+if(active?.optBoolean("agentOnline")==true) t("En línea","Online") else t("Sin conexión","Offline"),
                        color=supportMuted,fontSize=11.sp,maxLines=1)
                }
                if(active!=null)StatusChip(active.optString("status"),language)
            }
            if(showSpamWarning){
                val shape=RoundedCornerShape(16.dp)
                Row(Modifier.fillMaxWidth()
                    .padding(horizontal=12.dp)
                    .background(supportPanel,shape)
                    .border(1.dp,supportAmber,shape)
                    .padding(horizontal=14.dp,vertical=12.dp),
                    verticalAlignment=Alignment.CenterVertically,
                    horizontalArrangement=Arrangement.spacedBy(12.dp)){
                    Icon(Icons.Outlined.WarningAmber,null,tint=supportAmber,
                        modifier=Modifier.size(19.dp))
                    Text(if(suspended)
                        t("Tu acceso a soporte está suspendido temporalmente hasta las %s.",
                            "Your access to support is temporarily suspended until %s.")
                            .format(suspendedUntilText)
                    else t("Has creado varios tickets de soporte hoy. Si sigues creando tickets nuevos, tu acceso a soporte se suspenderá temporalmente (1 hora) y tu cuenta podría correr riesgo de suspensión si continúas.",
                        "You have created several support tickets today. If you keep creating new tickets, your access to support will be suspended temporarily (1 hour) and your account could be at risk of suspension if you continue."),
                        color=supportText,fontSize=12.sp,lineHeight=18.sp)
                }
            }
            LazyColumn(modifier=Modifier.weight(1f).fillMaxWidth(),
                state=scroll,contentPadding=PaddingValues(horizontal=4.dp,vertical=14.dp),
                verticalArrangement=Arrangement.spacedBy(5.dp)){
                itemsIndexed(displayItems,key={index,item->when(item){
                    is ChatItem.Day->"day-${item.at}-$index"
                    is ChatItem.Server->item.row.optString("id").ifBlank{"srv-$index"}
                    is ChatItem.Local->"pending-${item.pending.key}"
                    ChatItem.Welcome->"welcome"
                }}){index,item->
                    when(item){
                        is ChatItem.Day->ChatDayDivider(item.at,language)
                        is ChatItem.Server->{
                            val row=item.row
                            if(row.optString("sender")=="user"){
                                val atMs=parseIsoMs(row.optString("at"))?:Long.MAX_VALUE
                                OwnBubble(row,language,
                                    read=staffReadAtMs!=null && atMs<=staffReadAtMs)
                            }else{
                                val previous=(displayItems.getOrNull(index-1)
                                    as? ChatItem.Server)?.row
                                val groupStart=previous==null ||
                                    previous.optString("sender")=="user"
                                AgentBubble(row,language,
                                    showAvatar=groupStart,showName=groupStart)
                            }
                        }
                        is ChatItem.Local->PendingBubble(item.pending,language){
                            retryPending(item.pending)
                        }
                        ChatItem.Welcome->WelcomeBubble(language)
                    }
                }
            }
            if(active?.optString("status")=="closed"){
                val shape=RoundedCornerShape(16.dp)
                Row(Modifier.fillMaxWidth()
                    .padding(horizontal=12.dp,vertical=12.dp)
                    .background(supportPanel,shape)
                    .border(1.dp,supportBorder,shape)
                    .padding(horizontal=14.dp,vertical=12.dp),
                    verticalAlignment=Alignment.CenterVertically,
                    horizontalArrangement=Arrangement.spacedBy(12.dp)){
                    Icon(Icons.Outlined.Lock,null,tint=supportText,
                        modifier=Modifier.size(19.dp))
                    Column(verticalArrangement=Arrangement.spacedBy(3.dp)){
                        Text(t("Conversación cerrada","Conversation closed"),
                            color=supportText,fontSize=13.sp,fontWeight=FontWeight.SemiBold)
                        Text(t("Puedes consultar los mensajes anteriores.",
                            "You can still read earlier messages."),
                            color=supportMuted,fontSize=11.sp)
                    }
                }
            }else{
                Column(Modifier.fillMaxWidth().padding(horizontal=12.dp,vertical=8.dp),
                    verticalArrangement=Arrangement.spacedBy(6.dp)){
                    Row(Modifier.fillMaxWidth()
                        .background(supportPanel,RoundedCornerShape(28.dp))
                        .border(1.dp,supportBorder,RoundedCornerShape(28.dp))
                        .padding(start=6.dp,end=6.dp,top=5.dp,bottom=5.dp),
                        verticalAlignment=Alignment.Bottom,
                        horizontalArrangement=Arrangement.spacedBy(8.dp)){
                        IconButton(onClick={},enabled=false,
                            modifier=Modifier.size(40.dp)){
                            Icon(Icons.Outlined.AttachFile,
                                t("Próximamente: enviar captura",
                                    "Coming soon: send a screenshot"),
                                tint=supportMuted,modifier=Modifier.size(20.dp))
                        }
                        BasicTextField(value=text,
                            onValueChange={text=it.take(4000)},
                            modifier=Modifier.weight(1f),enabled=!busy&&!suspended,
                            maxLines=4,cursorBrush=SolidColor(supportText),
                            textStyle=TextStyle(color=supportText,fontSize=14.sp,
                                lineHeight=20.sp),
                            decorationBox={inner->
                                Box(Modifier.padding(vertical=12.dp)){
                                    if(text.isBlank())Text(
                                        t("Escribe un mensaje","Write a message"),
                                        color=supportMuted,fontSize=14.sp)
                                    inner()
                                }
                            })
                        IconButton(onClick={sendNow()},
                            enabled=!cannotSend(),
                            modifier=Modifier.size(40.dp)
                                .background(if(cannotSend())Color(0xFF444444)
                                    else supportText,CircleShape)){
                            if(busy)CircularProgressIndicator(
                                color=Color.Black,strokeWidth=2.dp,
                                modifier=Modifier.size(18.dp))
                            else Icon(Icons.Outlined.Send,t("Enviar","Send"),
                                tint=if(cannotSend())supportMuted else Color.Black,
                                modifier=Modifier.size(19.dp))
                        }
                    }
                    Row(Modifier.fillMaxWidth(),
                        horizontalArrangement=Arrangement.SpaceBetween){
                        Text(t("Próximamente: enviar captura",
                            "Coming soon: send a screenshot"),
                            color=supportMuted,fontSize=10.sp)
                        if(text.length>3500)
                            Text("${text.length} / 4.000",color=supportMuted,
                                fontSize=10.sp)
                    }
                    if(suspended){
                        Text(t("Soporte suspendido temporalmente. Podrás escribir de nuevo en %s.",
                            "Support is temporarily suspended. You will be able to write again in %s.")
                            .format(countdown),
                            color=supportAmber,fontSize=12.sp)
                    }
                }
            }
        }else{
            Row(Modifier.fillMaxWidth().background(supportPanel)
                .padding(horizontal=5.dp,vertical=9.dp),
                verticalAlignment=Alignment.CenterVertically,
                horizontalArrangement=Arrangement.spacedBy(7.dp)){
                IconButton(onClick=onExit,modifier=Modifier.size(42.dp)){
                    Icon(Icons.Outlined.ArrowBack,t("Volver","Back"),tint=supportText)
                }
                Column(Modifier.weight(1f)){
                    Row(verticalAlignment=Alignment.CenterVertically,
                        horizontalArrangement=Arrangement.spacedBy(8.dp)){
                        Text(t("Mensajes","Messages"),color=supportText,
                            fontSize=20.sp,fontWeight=FontWeight.Bold)
                        UnreadPill(unreadTotal)
                    }
                    Text(t("Asistencia privada de SP-DECODE",
                        "Private SP-DECODE support"),color=supportMuted,
                        fontSize=11.sp,maxLines=1)
                }
                Button(onClick={newChat=true;text="";error=null},
                    contentPadding=PaddingValues(horizontal=12.dp,vertical=8.dp),
                    colors=ButtonDefaults.buttonColors(containerColor=supportText,
                        contentColor=Color.Black)){
                    Icon(Icons.Outlined.Add,null,modifier=Modifier.size(17.dp))
                    Spacer(Modifier.width(3.dp))
                    Text(t("Nuevo","New"),fontSize=11.sp)
                }
            }
            if(inbox==null && !loadError){
                // Estado de carga real: skeleton de 3 filas, nunca el falso vacío.
                Column(Modifier.fillMaxWidth().padding(horizontal=12.dp,vertical=6.dp),
                    verticalArrangement=Arrangement.spacedBy(9.dp)){
                    repeat(3){
                        Row(Modifier.fillMaxWidth()
                            .background(supportPanel,RoundedCornerShape(20.dp))
                            .padding(horizontal=13.dp,vertical=15.dp),
                            verticalAlignment=Alignment.CenterVertically,
                            horizontalArrangement=Arrangement.spacedBy(13.dp)){
                            Box(Modifier.size(44.dp)
                                .background(supportElevated,CircleShape))
                            Column(Modifier.weight(1f),
                                verticalArrangement=Arrangement.spacedBy(8.dp)){
                                Box(Modifier.fillMaxWidth(0.6f).height(14.dp)
                                    .background(supportElevated,RoundedCornerShape(4.dp)))
                                Box(Modifier.fillMaxWidth(0.85f).height(12.dp)
                                    .background(supportElevated,RoundedCornerShape(4.dp)))
                            }
                        }
                    }
                }
            }else if(inbox==null && loadError){
                Column(Modifier.fillMaxWidth().padding(24.dp),
                    horizontalAlignment=Alignment.CenterHorizontally,
                    verticalArrangement=Arrangement.spacedBy(16.dp)){
                    Text(t("No se pudieron cargar las conversaciones",
                        "Could not load conversations"),
                        color=supportError,fontSize=13.sp)
                    Button(onClick={loadTick++},
                        colors=ButtonDefaults.buttonColors(
                            containerColor=supportText,contentColor=Color.Black)){
                        Text(t("Reintentar","Retry"))
                    }
                }
            }else{
                Column(Modifier.fillMaxWidth().padding(horizontal=12.dp),
                    verticalArrangement=Arrangement.spacedBy(9.dp)){
                    Row(Modifier.fillMaxWidth()
                        .background(supportPanel,RoundedCornerShape(20.dp))
                        .border(1.dp,supportBorder,RoundedCornerShape(20.dp))
                        .padding(horizontal=13.dp,vertical=4.dp),
                        verticalAlignment=Alignment.CenterVertically,
                        horizontalArrangement=Arrangement.spacedBy(8.dp)){
                        Icon(Icons.Outlined.Search,null,tint=supportMuted,
                            modifier=Modifier.size(19.dp))
                        BasicTextField(value=search,
                            onValueChange={search=it},
                            modifier=Modifier.weight(1f),singleLine=true,
                            cursorBrush=SolidColor(supportText),
                            textStyle=TextStyle(color=supportText,fontSize=14.sp),
                            decorationBox={inner->
                                Box(Modifier.padding(vertical=11.dp)){
                                    if(search.isBlank())Text(
                                        t("Buscar conversaciones","Search conversations"),
                                        color=supportMuted,fontSize=14.sp)
                                    inner()
                                }
                            })
                    }
                    Row(horizontalArrangement=Arrangement.spacedBy(8.dp)){
                        listOf("all" to t("Todos","All"),
                            "open" to t("Abiertos","Open"),
                            "answered" to t("Respondido","Answered"),
                            "closed" to t("Cerrado","Closed")).forEach{(id,label)->
                            val selected=filter==id
                            Box(Modifier
                                .background(if(selected)supportText else supportPanel,
                                    RoundedCornerShape(50))
                                .border(.8.dp,supportBorder,RoundedCornerShape(50))
                                .clickable{filter=id}
                                .padding(horizontal=13.dp,vertical=8.dp),
                                contentAlignment=Alignment.Center){
                                Text(label,
                                    color=if(selected)Color.Black else supportText,
                                    fontSize=12.sp,fontWeight=FontWeight.SemiBold)
                            }
                        }
                    }
                }
                val visible=threads.filter{thread->
                    val statusOk=when(filter){
                        "open"->thread.optString("status")!="closed"
                        "answered"->thread.optString("status")=="answered"
                        "closed"->thread.optString("status")=="closed"
                        else->true
                    }
                    if(!statusOk)return@filter false
                    if(search.isBlank())return@filter true
                    val query=search.trim().lowercase()
                    val all=thread.optJSONArray("messages")
                    val last=all?.optJSONObject((all.length()-1).coerceAtLeast(0))
                    thread.optString("subject").lowercase().contains(query) ||
                        last?.optString("text").orEmpty().lowercase().contains(query)
                }
                if(visible.isEmpty()){
                    Column(Modifier.fillMaxWidth().padding(24.dp),
                        horizontalAlignment=Alignment.CenterHorizontally,
                        verticalArrangement=Arrangement.spacedBy(16.dp)){
                        Text(if(search.isNotBlank()||filter!="all")
                            t("No hay conversaciones con ese filtro.",
                                "No conversations match that filter.")
                        else t("Todavía no tienes conversaciones.",
                            "You have no conversations yet."),
                            color=supportMuted,fontSize=13.sp)
                        if(search.isBlank()&&filter=="all"){
                            Button(onClick={newChat=true;text="";error=null},
                                colors=ButtonDefaults.buttonColors(
                                    containerColor=supportText,
                                    contentColor=Color.Black)){
                                Text(t("Escribir a soporte","Write to support"))
                            }
                        }
                    }
                }else{
                    LazyColumn(modifier=Modifier.weight(1f)
                            .padding(horizontal=12.dp,vertical=6.dp),
                        verticalArrangement=Arrangement.spacedBy(9.dp)){
                        itemsIndexed(visible,key={_,it->it.optString("id")}){_,thread->
                            val unread=threadUnread(thread)
                            val all=thread.optJSONArray("messages")
                            val last=all?.optJSONObject((all.length()-1).coerceAtLeast(0))
                            val lastFromAgent=last?.optString("sender")=="admin"
                            val lastAvatar=last?.optJSONObject("agent")
                                ?.optString("avatar")?.takeIf{it.isNotBlank()}
                            val rowAvatar=if(lastFromAgent)lastAvatar
                                else CommerceSession.user?.avatar
                            Row(Modifier.fillMaxWidth()
                                .background(supportPanel,RoundedCornerShape(20.dp))
                                .border(1.dp,supportBorder,RoundedCornerShape(20.dp))
                                .clickable{
                                    activeId=thread.optString("id")
                                    newChat=false;text="";error=null
                                }
                                .padding(horizontal=13.dp,vertical=15.dp),
                                verticalAlignment=Alignment.CenterVertically,
                                horizontalArrangement=Arrangement.spacedBy(13.dp)){
                                CommerceAvatar(rowAvatar,Modifier.size(44.dp))
                                Column(Modifier.weight(1f),
                                    verticalArrangement=Arrangement.spacedBy(6.dp)){
                                    Row(verticalAlignment=Alignment.CenterVertically){
                                        Text(thread.optString("subject"),color=supportText,
                                            fontSize=16.sp,
                                            fontWeight=if(unread>0)FontWeight.Bold
                                                else FontWeight.SemiBold,
                                            maxLines=1,overflow=TextOverflow.Ellipsis,
                                            modifier=Modifier.weight(1f))
                                        Text(chatTime(thread.optString("last_message_at"),true),
                                            color=supportMuted,fontSize=10.sp)
                                    }
                                    Text((if(lastFromAgent)
                                        t("Yamada","Yamada")
                                    else t("Tú","You"))+": " +
                                        (last?.optString("text")?:""),
                                        color=supportMuted,fontSize=13.sp,maxLines=1,
                                        overflow=TextOverflow.Ellipsis)
                                    Row(verticalAlignment=Alignment.CenterVertically,
                                        horizontalArrangement=Arrangement.spacedBy(8.dp)){
                                        StatusChip(thread.optString("status"),language)
                                        UnreadPill(unread)
                                    }
                                }
                                Icon(Icons.Outlined.ChevronRight,null,
                                    tint=Color(0xFF777777),modifier=Modifier.size(20.dp))
                            }
                        }
                    }
                }
            }
        }
        if(busy)LinearProgressIndicator(Modifier.fillMaxWidth(),color=supportText)
        if(error!=null)Text(error.orEmpty(),color=supportError,fontSize=12.sp,
            modifier=Modifier.padding(horizontal=16.dp))
    }
}
