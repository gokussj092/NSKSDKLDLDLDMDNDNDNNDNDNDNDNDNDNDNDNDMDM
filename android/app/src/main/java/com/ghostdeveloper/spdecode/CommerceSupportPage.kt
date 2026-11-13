package com.ghostdeveloper.spdecode

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.lazy.itemsIndexed
import androidx.compose.foundation.text.BasicTextField
import androidx.compose.foundation.lazy.rememberLazyListState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.SolidColor
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
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

private val chatWhite=Color(0xFFF6F6F6)
private val chatMuted=Color(0xFFA9A9A9)
private val chatPanel=Color(0xFF1C1C1C)
private val chatGreen=Color(0xFFB8DCC0)
private val chatLine=Color(0xFF353535)
private val chatOutgoing=Color(0xFF244233)
private val chatIncoming=Color(0xFF262626)

private fun chatTime(input:String,full:Boolean=false):String = runCatching{
    val date=Date.from(Instant.parse(input))
    if(full)DateFormat.getDateTimeInstance(DateFormat.SHORT,DateFormat.SHORT).format(date)
    else DateFormat.getTimeInstance(DateFormat.SHORT).format(date)
}.getOrDefault("")

private fun chatDateKey(value:String):String=runCatching{
    Instant.parse(value).atZone(ZoneId.systemDefault()).toLocalDate().toString()
}.getOrDefault("")

@Composable
private fun ChatDayDivider(input:String,language:String){
    val label=runCatching{
        DateFormat.getDateInstance(DateFormat.MEDIUM,Locale.forLanguageTag(language))
            .format(Date.from(Instant.parse(input)))
    }.getOrDefault("")
    if(label.isNotEmpty()){
        Row(Modifier.fillMaxWidth().padding(vertical=12.dp),
            horizontalArrangement=Arrangement.Center){
            Text(label,color=chatMuted,fontSize=11.sp,
                modifier=Modifier.background(Color(0xFF292929),RoundedCornerShape(40.dp))
                    .padding(horizontal=13.dp,vertical=6.dp))
        }
    }
}

@Composable
private fun SupportAvatar(letters:String,fromTeam:Boolean=false){
    Box(Modifier.size(44.dp)
        .background(if(fromTeam)Color(0xFF31533F) else Color(0xFF373737),CircleShape),
        contentAlignment=Alignment.Center){
        Text(letters.take(2).uppercase(),color=chatWhite,fontWeight=FontWeight.SemiBold,
            fontSize=15.sp)
    }
}
@Composable
private fun StatusChip(status:String,language:String){
    val text=when(status){
        "answered"->CommerceI18n.translate(language,"Respondido","Answered")
        "closed"->CommerceI18n.translate(language,"Cerrado","Closed")
        else->CommerceI18n.translate(language,"Pendiente","Pending")
    }
    val tint=when(status){
        "answered"->chatGreen
        "closed"->chatMuted
        else->Color(0xFFFFCF8F)
    }
    Box(Modifier.background(Color(0xFF303030),RoundedCornerShape(50))
        .padding(horizontal=10.dp,vertical=5.dp)){
        Text(text,color=tint,fontWeight=FontWeight.Medium,fontSize=11.sp)
    }
}
@Composable
private fun SupportBubble(row:JSONObject,language:String){
    val mine=row.optString("sender")=="user"
    val agent=row.optJSONObject("agent")
    val person=agent?.optString("name")?.takeIf{it.isNotBlank()}?:"SP-DECODE"
    val role=when(agent?.optString("role")){
        "owner","admin"->CommerceI18n.translate(language,"Administración","Administrator")
        "moderator"->CommerceI18n.translate(language,"Moderación","Moderation")
        else->CommerceI18n.translate(language,"Soporte técnico","Technical support")
    }
    val shape=RoundedCornerShape(topStart=18.dp,topEnd=18.dp,
        bottomStart=if(mine)18.dp else 5.dp,bottomEnd=if(mine)5.dp else 18.dp)
    Row(Modifier.fillMaxWidth().padding(vertical=3.dp),
        verticalAlignment=Alignment.Bottom,
        horizontalArrangement=if(mine)Arrangement.End else Arrangement.Start){
        if(!mine)Box(Modifier.padding(end=8.dp,bottom=2.dp).size(28.dp)
            .background(Color(0xFF31533F),CircleShape),contentAlignment=Alignment.Center){
            Icon(Icons.Outlined.SupportAgent,null,tint=chatGreen,modifier=Modifier.size(17.dp))
        }
        Column(Modifier.fillMaxWidth(if(mine).83f else .82f)
            .background(if(mine)chatOutgoing else chatIncoming,shape)
            .border(.5.dp,if(mine)Color(0xFF3A6750) else chatLine,shape)
            .padding(horizontal=13.dp,vertical=10.dp),
            verticalArrangement=Arrangement.spacedBy(6.dp)){
            if(!mine)Text(person+" · "+role,color=chatGreen,
                fontSize=11.sp,fontWeight=FontWeight.Bold)
            Text(row.optString("text"),color=chatWhite,fontSize=14.sp,lineHeight=20.sp)
            Text(chatTime(row.optString("at")),color=Color(0xFFC0C8C1),
                fontSize=10.sp,modifier=Modifier.align(Alignment.End))
        }
    }
}

@Composable
internal fun CommerceSupportPage(language:String,auth:NativeCommerceAuth,
    report:Boolean,onSignIn:()->Unit){
    val t:(String,String)->String={es,en->CommerceI18n.translate(language,es,en)}
    val scope=rememberCoroutineScope()
    var inbox by remember{mutableStateOf<JSONObject?>(null)}
    var activeId by remember{mutableStateOf("")}
    var creating by remember{mutableStateOf(report)}
    var title by remember{mutableStateOf("")}
    var category by remember{mutableStateOf(if(report)"apk" else "technical")}
    var text by remember{mutableStateOf("")}
    var busy by remember{mutableStateOf(false)}
    var error by remember{mutableStateOf<String?>(null)}
    var categoryExpanded by remember{mutableStateOf(false)}
    val scroll=rememberLazyListState()
    val categories=linkedMapOf(
        "technical" to t("Asistencia técnica","Technical support"),
        "apk" to t("Error de análisis","Analysis error"),
        "payments" to t("Compras y pagos","Purchases and payments"),
        "account" to t("Cuenta y acceso","Account and access"),
        "other" to t("Otra consulta","Other inquiry"))
    LaunchedEffect(Unit){
        while(isActive){
            if(auth.sessionToken()!=null)runCatching{auth.supportInbox()}.onSuccess{inbox=it}
            delay(12_000)
        }
    }
    val itemsJson=inbox?.optJSONArray("threads")
    val threads=(0 until (itemsJson?.length()?:0))
        .mapNotNull{itemsJson?.optJSONObject(it)}
    val active=threads.firstOrNull{it.optString("id")==activeId}
    val entries=active?.optJSONArray("messages")
    val messages=(0 until(entries?.length()?:0)).mapNotNull{entries?.optJSONObject(it)}
    LaunchedEffect(activeId,messages.size){
        if(activeId.isNotEmpty()&&messages.isNotEmpty())
            scroll.animateScrollToItem(messages.lastIndex)
    }
    fun cannotSend():Boolean = busy||text.trim().isEmpty()
    Column(Modifier.fillMaxSize(),
        verticalArrangement=Arrangement.spacedBy(12.dp)){
        if(auth.sessionToken()==null){
            Column(Modifier.fillMaxWidth().padding(24.dp),
                horizontalAlignment=Alignment.CenterHorizontally,
                verticalArrangement=Arrangement.spacedBy(16.dp)){
                Icon(Icons.Outlined.SupportAgent,null,tint=chatGreen,
                    modifier=Modifier.size(52.dp))
                Text(t("Centro de asistencia","Support center"),
                    color=chatWhite,fontSize=22.sp,fontWeight=FontWeight.Bold)
                Button(onClick=onSignIn,
                    colors=ButtonDefaults.buttonColors(containerColor=chatWhite,
                        contentColor=Color.Black)){
                    Text(t("Iniciar sesión","Sign in"))
                }
            }
        }else if(active!=null){
            Row(Modifier.fillMaxWidth().padding(bottom=3.dp),
                verticalAlignment=Alignment.CenterVertically,
                horizontalArrangement=Arrangement.spacedBy(12.dp)){
                IconButton(onClick={activeId="";text="";creating=false},
                    modifier=Modifier.size(42.dp)){
                    Icon(Icons.Outlined.ArrowBack,
                        t("Conversaciones","Conversations"),tint=chatWhite)
                }
                SupportAvatar("SP",true)
                Column(Modifier.weight(1f)){
                    Text(active.optString("subject"),color=chatWhite,fontSize=16.sp,
                        fontWeight=FontWeight.SemiBold,maxLines=1,
                        overflow=TextOverflow.Ellipsis)
                    Text(t("Chat privado de soporte","Private support conversation"),
                        color=chatMuted,fontSize=11.sp,maxLines=1)
                }
                StatusChip(active.optString("status"),language)
            }
            HorizontalDivider(color=chatLine)
            LazyColumn(modifier=Modifier.weight(1f).fillMaxWidth(),
                state=scroll,contentPadding=PaddingValues(vertical=10.dp),
                verticalArrangement=Arrangement.spacedBy(5.dp)){
                itemsIndexed(messages,key={_,item->item.optString("id")}){index,message->
                    if(index==0||chatDateKey(messages[index-1].optString("at"))!=
                        chatDateKey(message.optString("at")))
                        ChatDayDivider(message.optString("at"),language)
                    SupportBubble(message,language)
                }
            }
            if(active.optString("status")!="closed"){
                Row(Modifier.fillMaxWidth()
                    .background(chatPanel,RoundedCornerShape(27.dp))
                    .border(1.dp,chatLine,RoundedCornerShape(27.dp))
                    .padding(start=14.dp,end=6.dp,top=5.dp,bottom=5.dp),
                    verticalAlignment=Alignment.Bottom,
                    horizontalArrangement=Arrangement.spacedBy(8.dp)){
                    BasicTextField(value=text,onValueChange={text=it.take(4000)},
                        modifier=Modifier.weight(1f),enabled=!busy,maxLines=4,
                        cursorBrush=SolidColor(chatGreen),
                        textStyle=TextStyle(color=chatWhite,fontSize=14.sp,lineHeight=20.sp),
                        decorationBox={inner->
                            Box(Modifier.padding(vertical=12.dp)){
                                if(text.isBlank())Text(t("Escribe un mensaje","Write a message"),
                                    color=chatMuted,fontSize=14.sp)
                                inner()
                            }
                        })
                    IconButton(
                        onClick={
                            scope.launch{
                                busy=true;error=null
                                try{
                                    auth.sendSupportMessage(activeId,text.trim())
                                    text="";inbox=auth.supportInbox()
                                }catch(e:CancellationException){throw e}
                                catch(_:Exception){error=t("No se pudo enviar el mensaje",
                                    "Unable to send message")}
                                finally{busy=false}
                            }
                        },
                        enabled=!cannotSend(),
                        modifier=Modifier.size(40.dp)
                            .background(if(cannotSend())Color(0xFF444444) else chatGreen,
                                CircleShape)){
                        if(busy)CircularProgressIndicator(
                            color=chatWhite,strokeWidth=2.dp,modifier=Modifier.size(18.dp))
                        else Icon(Icons.Outlined.Send,t("Enviar","Send"),
                            tint=if(cannotSend())chatMuted else Color.Black,
                            modifier=Modifier.size(19.dp))
                    }
                }
            }else{
                Text(t("Conversación cerrada","Conversation closed"),
                    color=chatMuted,fontSize=13.sp,
                    modifier=Modifier.fillMaxWidth().padding(12.dp))
            }
        }else if(creating){
            Row(verticalAlignment=Alignment.CenterVertically){
                IconButton(onClick={creating=false;text="";error=null}){
                    Icon(Icons.Outlined.ArrowBack,null,tint=chatWhite)
                }
                Text(t("Nueva conversación","New conversation"),color=chatWhite,
                    fontSize=20.sp,fontWeight=FontWeight.Bold)
            }
            Column(Modifier.fillMaxWidth()
                .background(chatPanel,RoundedCornerShape(22.dp)).padding(16.dp),
                verticalArrangement=Arrangement.spacedBy(14.dp)){
                Box{
                    OutlinedButton(onClick={categoryExpanded=true},
                        modifier=Modifier.fillMaxWidth()){
                        Text(categories[category]?:category,
                            modifier=Modifier.weight(1f),color=chatWhite)
                        Icon(Icons.Outlined.ArrowDropDown,null,tint=chatWhite)
                    }
                    DropdownMenu(expanded=categoryExpanded,
                        onDismissRequest={categoryExpanded=false}){
                        categories.forEach{(id,name)->
                            DropdownMenuItem(text={Text(name)},
                                onClick={category=id;categoryExpanded=false})
                        }
                    }
                }
                OutlinedTextField(title,{title=it.take(100)},singleLine=true,
                    modifier=Modifier.fillMaxWidth(),
                    label={Text(t("Asunto","Subject"))})
                OutlinedTextField(text,{text=it.take(4000)},
                    modifier=Modifier.fillMaxWidth(),
                    minLines=4,maxLines=7,
                    label={Text(t("Describe tu consulta","Describe your issue"))})
                Row(Modifier.fillMaxWidth(),
                    horizontalArrangement=Arrangement.End){
                    Button(onClick={
                        scope.launch{
                            busy=true;error=null
                            try{
                                val result=auth.openSupportThread(title.trim(),category,text.trim())
                                activeId=result.getString("id")
                                inbox=auth.supportInbox()
                                title="";text="";creating=false
                            }catch(e:CancellationException){throw e}
                            catch(_:Exception){error=t("No se pudo crear la conversación",
                                "Could not create conversation")}
                            finally{busy=false}
                        }
                    },enabled=!busy&&title.trim().length>=4&&text.trim().isNotEmpty(),
                        colors=ButtonDefaults.buttonColors(
                            containerColor=chatWhite,contentColor=Color.Black)){
                        Icon(Icons.Outlined.Send,null,
                            modifier=Modifier.size(18.dp))
                        Spacer(Modifier.width(7.dp))
                        Text(t("Enviar","Send"))
                    }
                }
            }
            Spacer(Modifier.weight(1f))
        }else{
            Row(Modifier.fillMaxWidth().padding(vertical=4.dp),
                verticalAlignment=Alignment.CenterVertically){
                Column(Modifier.weight(1f)){
                    Text(t("Mensajes","Messages"),color=chatWhite,
                        fontSize=24.sp,fontWeight=FontWeight.Bold)
                    Text(t("Asistencia privada de SP-DECODE",
                        "Private SP-DECODE support"),color=chatMuted,fontSize=12.sp)
                }
                FilledTonalButton(onClick={creating=true;text="";error=null},
                    contentPadding=PaddingValues(horizontal=14.dp,vertical=9.dp),
                    colors=ButtonDefaults.filledTonalButtonColors(
                        containerColor=chatWhite,contentColor=Color.Black)){
                    Icon(Icons.Outlined.Add,null,modifier=Modifier.size(18.dp))
                    Spacer(Modifier.width(5.dp))
                    Text(t("Nuevo","New"),fontSize=12.sp)
                }
            }
            HorizontalDivider(color=chatLine)
            LazyColumn(modifier=Modifier.weight(1f),
                verticalArrangement=Arrangement.spacedBy(9.dp)){
                items(threads,key={it.optString("id")}){thread->
                    val all=thread.optJSONArray("messages")
                    val last=all?.optJSONObject((all.length()-1).coerceAtLeast(0))
                    Row(Modifier.fillMaxWidth()
                        .background(chatPanel,RoundedCornerShape(18.dp))
                        .border(1.dp,chatLine,RoundedCornerShape(18.dp))
                        .clickable{
                            activeId=thread.optString("id");text="";error=null
                        }
                        .padding(horizontal=13.dp,vertical=15.dp),
                        verticalAlignment=Alignment.CenterVertically,
                        horizontalArrangement=Arrangement.spacedBy(13.dp)){
                        SupportAvatar("SP",true)
                        Column(Modifier.weight(1f),
                            verticalArrangement=Arrangement.spacedBy(6.dp)){
                            Row(verticalAlignment=Alignment.CenterVertically){
                                Text(thread.optString("subject"),color=chatWhite,
                                    fontSize=16.sp,fontWeight=FontWeight.SemiBold,
                                    maxLines=1,overflow=TextOverflow.Ellipsis,
                                    modifier=Modifier.weight(1f))
                                Text(chatTime(thread.optString("last_message_at"),true),
                                    color=chatMuted,fontSize=10.sp)
                            }
                            Text(last?.optString("text")?:"",
                                color=chatMuted,fontSize=13.sp,maxLines=1,
                                overflow=TextOverflow.Ellipsis)
                            StatusChip(thread.optString("status"),language)
                        }
                        Icon(Icons.Outlined.ChevronRight,null,
                            tint=Color(0xFF777777),modifier=Modifier.size(20.dp))
                    }
                }
            }
            if(threads.isEmpty()){
                Text(t("Todavía no tienes conversaciones.",
                    "You have no conversations yet."),color=chatMuted,fontSize=13.sp)
            }
        }
        if(busy)LinearProgressIndicator(Modifier.fillMaxWidth(),color=chatGreen)
        if(error!=null)Text(error.orEmpty(),color=Color(0xFFFF8585),fontSize=12.sp)
    }
}
