package com.ghostdeveloper.spdecode

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.CircleShape
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
import java.text.DateFormat
import java.time.Instant
import java.util.Date
import java.util.Locale

private val inboxPanel=Color(0xFF232323)
private val inboxEdge=Color(0xFF404040)
private val inboxText=Color(0xFFF6F6F6)
private val inboxMuted=Color(0xFFB4B4B4)
private val inboxAccent=Color(0xFFB8DCC0)
private fun displayTime(value:String,lang:String):String=runCatching{
    DateFormat.getDateTimeInstance(DateFormat.MEDIUM,DateFormat.SHORT,
        Locale.forLanguageTag(lang)).format(Date.from(Instant.parse(value)))
}.getOrDefault("")
private fun rows(json:JSONObject?,key:String):List<JSONObject>{
    val array=json?.optJSONArray(key)?:return emptyList()
    return (0 until array.length()).mapNotNull{array.optJSONObject(it)}
}
@Composable
internal fun CommerceNotificationCenter(language:String,auth:NativeCommerceAuth,
    onSignIn:()->Unit,onOpen:(String)->Unit){
    val scope=rememberCoroutineScope()
    val tr:(String,String)->String={es,en->CommerceI18n.translate(language,es,en)}
    var data by remember{mutableStateOf<JSONObject?>(null)}
    var loading by remember{mutableStateOf(false)}
    var error by remember{mutableStateOf(false)}
    fun reload(){
        if(loading)return
        scope.launch{
            loading=true;error=false
            try{data=auth.notificationInbox()}
            catch(e:CancellationException){throw e}
            catch(_:Exception){error=true}
            finally{loading=false}
        }
    }
    LaunchedEffect(Unit){reload()}
    Column(Modifier.fillMaxSize(),verticalArrangement=Arrangement.spacedBy(13.dp)){
        Row(Modifier.fillMaxWidth(),verticalAlignment=Alignment.CenterVertically,
            horizontalArrangement=Arrangement.SpaceBetween){
            Column{
                Text(tr("Notificaciones","Notifications"),color=inboxText,
                    fontSize=25.sp,fontWeight=FontWeight.Bold)
                val count=data?.optInt("unread",0)?:0
                Text(if(count>0)tr("$count sin leer","$count unread")
                     else tr("Todo al día","You're all caught up"),
                    color=inboxMuted,fontSize=12.sp)
            }
            Row{
                IconButton(onClick={reload()},enabled=!loading){
                    Icon(Icons.Outlined.Refresh,tr("Actualizar","Refresh"),tint=inboxText)
                }
                IconButton(onClick={
                    scope.launch{
                        try{auth.markAllNotifications();data=auth.notificationInbox()}
                        catch(_:Exception){error=true}
                    }
                },enabled=!loading && (data?.optInt("unread",0)?:0)>0){
                    Icon(Icons.Outlined.DoneAll,tr("Marcar todo leído","Mark all read"),
                        tint=inboxAccent)
                }
            }
        }
        if(loading)LinearProgressIndicator(Modifier.fillMaxWidth(),color=inboxAccent)
        if(error)Text(tr("No se pudieron cargar los avisos. Inténtalo de nuevo.",
            "Notifications are unavailable. Try again."),color=Color(0xFFFF8A8A),fontSize=13.sp)
        if(auth.sessionToken()==null){
            Button(onClick=onSignIn){Text(tr("Iniciar sesión","Sign in"))}
        }else{
            val notices=rows(data,"notices")
            if(!loading&&notices.isEmpty()){
                Column(Modifier.fillMaxWidth().padding(top=60.dp),
                    horizontalAlignment=Alignment.CenterHorizontally){
                    Icon(Icons.Outlined.NotificationsNone,null,tint=inboxMuted,
                        modifier=Modifier.size(54.dp))
                    Spacer(Modifier.height(14.dp))
                    Text(tr("Aún no tienes notificaciones","No notifications yet"),
                        color=inboxText)
                }
            }
            LazyColumn(Modifier.weight(1f),verticalArrangement=Arrangement.spacedBy(9.dp)){
                items(notices,key={it.optString("id")}){item->
                    val kind=item.optString("kind")
                    val unread=item.isNull("read_at")
                    val icon=when(kind){
                        "support"->Icons.Outlined.SupportAgent
                        "purchase"->Icons.Outlined.ReceiptLong
                        "security"->Icons.Outlined.Shield
                        else->Icons.Outlined.Campaign
                    }
                    Row(Modifier.fillMaxWidth()
                        .background(if(unread)Color(0xFF25382D) else inboxPanel,
                            RoundedCornerShape(18.dp))
                        .border(1.dp,if(unread)Color(0xFF456953) else inboxEdge,
                            RoundedCornerShape(18.dp))
                        .clickable {
                            scope.launch{
                                if(unread)runCatching{auth.markNotification(item.optString("id"))}
                                onOpen(when(kind){"support"->"support";"purchase"->"orders";
                                    "security"->"security";else->"account"})
                            }
                        }.padding(14.dp),
                        verticalAlignment=Alignment.Top,horizontalArrangement=Arrangement.spacedBy(12.dp)){
                        Box(Modifier.size(43.dp).background(Color(0xFF303A33),CircleShape),
                            contentAlignment=Alignment.Center){
                            Icon(icon,null,tint=inboxAccent,modifier=Modifier.size(23.dp))
                        }
                        Column(Modifier.weight(1f),verticalArrangement=Arrangement.spacedBy(4.dp)){
                            Row(verticalAlignment=Alignment.CenterVertically){
                                Text(item.optString("title"),color=inboxText,
                                    fontWeight=FontWeight.SemiBold,fontSize=15.sp,
                                    modifier=Modifier.weight(1f))
                                if(unread)Box(Modifier.size(7.dp).background(inboxAccent,CircleShape))
                            }
                            Text(item.optString("body"),color=inboxMuted,
                                fontSize=13.sp,lineHeight=19.sp)
                            Text(displayTime(item.optString("created_at"),language),
                                color=inboxMuted,fontSize=11.sp)
                        }
                    }
                }
            }
        }
    }
}

@Composable
internal fun CommerceActivityPage(language:String,auth:NativeCommerceAuth,onSignIn:()->Unit){
    val scope=rememberCoroutineScope()
    val tr:(String,String)->String={es,en->CommerceI18n.translate(language,es,en)}
    var data by remember{mutableStateOf<JSONObject?>(null)}
    var busy by remember{mutableStateOf(false)}
    var error by remember{mutableStateOf(false)}
    var filter by remember{mutableStateOf("all")}
    fun reload(){
        scope.launch{
            busy=true;error=false
            try{data=auth.accountActivity()}
            catch(e:CancellationException){throw e}
            catch(_:Exception){error=true}
            finally{busy=false}
        }
    }
    LaunchedEffect(Unit){reload()}
    Column(Modifier.fillMaxSize(),verticalArrangement=Arrangement.spacedBy(13.dp)){
        Row(Modifier.fillMaxWidth(),verticalAlignment=Alignment.CenterVertically){
            Text(tr("Historial de operaciones","Activity history"),color=inboxText,
                fontSize=24.sp,fontWeight=FontWeight.Bold,modifier=Modifier.weight(1f))
            IconButton(onClick={reload()},enabled=!busy){
                Icon(Icons.Outlined.Refresh,null,tint=inboxText)
            }
        }
        Text(tr("Compras, créditos, análisis y canjes",
            "Purchases, credits, analyses and redemptions"),
            color=inboxMuted,fontSize=13.sp)
        Row(horizontalArrangement=Arrangement.spacedBy(7.dp)){
            listOf("all" to tr("Todo","All"),"order" to tr("Compras","Orders"),
                "credit" to tr("Créditos","Credits"),"analysis" to tr("Análisis","Analysis"))
                .forEach{(kind,label)->
                    FilterChip(selected=filter==kind,onClick={filter=kind},
                        label={Text(label,fontSize=11.sp,maxLines=1)})
                }
        }
        if(busy)LinearProgressIndicator(Modifier.fillMaxWidth(),color=inboxAccent)
        if(error)Text(tr("No se pudo cargar el historial","Could not load history"),
            color=Color(0xFFFF8585))
        if(auth.sessionToken()==null)Button(onClick=onSignIn){
            Text(tr("Iniciar sesión","Sign in"))
        }
        else{
            val entries=rows(data,"operations").filter{filter=="all"||it.optString("kind")==filter}
            if(!busy&&entries.isEmpty())Text(tr("No hay operaciones registradas",
                "No recorded activity"),color=inboxMuted)
            LazyColumn(Modifier.weight(1f),verticalArrangement=Arrangement.spacedBy(9.dp)){
                items(entries,key={it.optString("kind")+it.optString("id")}){item->
                    val kind=item.optString("kind")
                    val icon=when(kind){
                        "order"->Icons.Outlined.ReceiptLong
                        "credit"->Icons.Outlined.Toll
                        "analysis"->Icons.Outlined.Memory
                        else->Icons.Outlined.CardGiftcard
                    }
                    val title=when(kind){
                        "order"->tr("Compra","Purchase")
                        "credit"->tr("Movimiento de créditos","Credit movement")
                        "analysis"->tr("Análisis APK","APK analysis")
                        else->tr("Código de regalo","Gift redemption")
                    }
                    Row(Modifier.fillMaxWidth()
                        .background(inboxPanel,RoundedCornerShape(17.dp))
                        .border(1.dp,inboxEdge,RoundedCornerShape(17.dp))
                        .padding(14.dp),
                        horizontalArrangement=Arrangement.spacedBy(12.dp),
                        verticalAlignment=Alignment.CenterVertically){
                        Icon(icon,null,tint=inboxAccent,modifier=Modifier.size(25.dp))
                        Column(Modifier.weight(1f),verticalArrangement=Arrangement.spacedBy(4.dp)){
                            Text(title,color=inboxText,fontWeight=FontWeight.SemiBold)
                            Text(item.optString("status").replace('_',' '),
                                color=inboxMuted,fontSize=12.sp)
                            Text(displayTime(item.optString("at"),language),
                                color=inboxMuted,fontSize=11.sp)
                        }
                        if(kind=="credit"){
                            val delta=item.optInt("delta")
                            Text((if(delta>0)"+" else "")+delta,
                                color=if(delta>=0)inboxAccent else Color(0xFFFF8585),
                                fontWeight=FontWeight.Bold)
                        }else if(kind=="order"&&!item.isNull("amountCents")){
                            val n=item.optInt("amountCents")
                            Text("%s %.2f".format(Locale.US,item.optString("currency","USD"),n/100.0),
                                color=inboxText,fontSize=12.sp)
                        }
                    }
                }
            }
        }
    }
}
