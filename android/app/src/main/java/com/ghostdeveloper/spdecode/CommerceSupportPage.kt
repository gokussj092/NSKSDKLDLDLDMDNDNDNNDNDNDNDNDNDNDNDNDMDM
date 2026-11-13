package com.ghostdeveloper.spdecode

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
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
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.text.DateFormat
import java.util.Date

private val supportBg=Color(0xFF222222)
private val supportText=Color(0xFFF5F5F5)
private val supportAccent=Color(0xFFB8DCC0)
@Composable
internal fun CommerceSupportPage(language:String,auth:NativeCommerceAuth,report:Boolean,
    onSignIn:()->Unit){
    val local:(String,String)->String={es,en->CommerceI18n.translate(language,es,en)}
    val scope=rememberCoroutineScope()
    var inbox by remember {mutableStateOf<JSONObject?>(null)}
    var activeId by remember {mutableStateOf("")}
    var subject by remember {mutableStateOf("")}
    var message by remember {mutableStateOf("")}
    var category by remember {mutableStateOf(if(report)"apk" else "technical")}
    var creating by remember {mutableStateOf(report)}
    var loading by remember {mutableStateOf(false)}
    var error by remember {mutableStateOf<String?>(null)}
    val categories=linkedMapOf(
        "technical" to local("Soporte técnico","Technical support"),
        "apk" to local("Reportar error de análisis","Report analysis error"),
        "payments" to local("Compras y pagos","Purchases and billing"),
        "account" to local("Mi cuenta","My account"),
        "other" to local("Otra consulta","Other inquiry"))
    LaunchedEffect(Unit){
        while(isActive){
            if(auth.sessionToken()!=null){
                runCatching{auth.supportInbox()}.onSuccess{inbox=it}
            }
            delay(12_000L)
        }
    }
    val threads=inbox?.optJSONArray("threads")
    val list=(0 until (threads?.length()?:0)).mapNotNull{threads?.optJSONObject(it)}
    val active=list.firstOrNull{it.optString("id")==activeId}
    Column(verticalArrangement=Arrangement.spacedBy(16.dp)){
        Text(if(report)local("Reportar un problema","Report a problem")
            else local("Centro de soporte","Support center"),
            color=supportText,fontSize=28.sp,fontWeight=FontWeight.Bold)
        if(auth.sessionToken()==null){
            Button(onClick=onSignIn,modifier=Modifier.fillMaxWidth()){
                Text(local("Iniciar sesión para contactar soporte","Sign in to contact support"))
            }
        }else if(active==null){
            if(creating||list.isEmpty()){
                Column(Modifier.fillMaxWidth().background(supportBg,RoundedCornerShape(20.dp))
                    .padding(18.dp),verticalArrangement=Arrangement.spacedBy(14.dp)){
                    var menu by remember {mutableStateOf(false)}
                    Box {
                        OutlinedButton(onClick={menu=true},modifier=Modifier.fillMaxWidth()){
                            Text(categories[category].orEmpty(),modifier=Modifier.weight(1f))
                            Icon(Icons.Outlined.ArrowDropDown,null)
                        }
                        DropdownMenu(expanded=menu,onDismissRequest={menu=false}){
                            categories.forEach{(id,label)->
                                DropdownMenuItem(text={Text(label)},onClick={category=id;menu=false})
                            }
                        }
                    }
                    OutlinedTextField(subject,{subject=it.take(100)},modifier=Modifier.fillMaxWidth(),
                        label={Text(local("Asunto","Subject"))},singleLine=true)
                    OutlinedTextField(message,{message=it.take(4000)},modifier=Modifier.fillMaxWidth(),
                        label={Text(local("Describe tu consulta","Describe your issue"))},
                        minLines=4,maxLines=7)
                    Button(modifier=Modifier.fillMaxWidth(),
                        enabled=!loading&&subject.trim().length>=4&&message.isNotBlank(),
                        onClick={
                            scope.launch{
                                loading=true;error=null
                                try{
                                    val response=auth.openSupportThread(subject,category,message)
                                    activeId=response.getString("id")
                                    inbox=auth.supportInbox()
                                    subject="";message="";creating=false
                                }catch(e:CancellationException){throw e}
                                catch(_:Exception){
                                    error=local("No se pudo enviar el mensaje.","Message could not be sent.")
                                }finally{loading=false}
                            }
                        },colors=ButtonDefaults.buttonColors(containerColor=supportText,contentColor=Color.Black)){
                        Icon(Icons.Outlined.Send,null)
                        Spacer(Modifier.width(8.dp))
                        Text(local("Enviar mensaje","Send message"))
                    }
                }
                if(list.isNotEmpty()){
                    OutlinedButton(modifier=Modifier.fillMaxWidth(),onClick={creating=false}){
                        Text(local("Ver conversaciones","Show conversations"))
                    }
                }
            }else{
                Button(modifier=Modifier.fillMaxWidth(),onClick={creating=true},
                    colors=ButtonDefaults.buttonColors(containerColor=supportText,contentColor=Color.Black)){
                    Icon(Icons.Outlined.Add,null)
                    Spacer(Modifier.width(8.dp))
                    Text(local("Nueva consulta","New conversation"))
                }
                list.forEach{thread->
                    Column(Modifier.fillMaxWidth().background(supportBg,RoundedCornerShape(18.dp))
                        .padding(16.dp),verticalArrangement=Arrangement.spacedBy(5.dp)){
                        Text(thread.optString("subject"),color=supportText,
                            fontWeight=FontWeight.SemiBold)
                        Text(when(thread.optString("status")){
                            "answered"->local("Respondido","Answered")
                            "closed"->local("Cerrado","Closed")
                            else->local("En curso","In progress")
                        },color=supportAccent,fontSize=12.sp)
                        OutlinedButton(onClick={activeId=thread.getString("id")}){
                            Text(local("Abrir conversación","Open conversation"))
                        }
                    }
                }
            }
        }else{
            OutlinedButton(onClick={activeId="";creating=false}){
                Icon(Icons.Outlined.ArrowBack,null)
                Text(local("Conversaciones","Conversations"))
            }
            Text(active.optString("subject"),color=supportText,
                fontSize=19.sp,fontWeight=FontWeight.SemiBold)
            val messages=active.optJSONArray("messages")
            (0 until (messages?.length()?:0)).forEach{i->
                val row=messages?.optJSONObject(i)?:return@forEach
                val fromUser=row.optString("sender")=="user"
                Row(Modifier.fillMaxWidth(),
                    horizontalArrangement=if(fromUser)Arrangement.End else Arrangement.Start){
                    Column(Modifier.fillMaxWidth(.90f)
                        .background(if(fromUser)Color(0xFF2A4031) else supportBg,
                            RoundedCornerShape(17.dp)).padding(13.dp),
                        verticalArrangement=Arrangement.spacedBy(6.dp)){
                        val staff=row.optJSONObject("agent")
                        val staffName=staff?.optString("name")?.trim()
                            ?.takeIf{it.isNotBlank()}?:"SP-DECODE"
                        val staffRole=when(staff?.optString("role")){
                            "owner","admin"->local("Administración","Administrator")
                            else->local("Soporte técnico","Technical support")
                        }
                        Text(if(fromUser)local("Tú","You") else staffName+" · "+staffRole,
                            color=supportAccent,fontSize=11.sp,fontWeight=FontWeight.Bold)
                        Text(row.optString("text"),color=supportText,fontSize=14.sp)
                        val date=runCatching{Date.from(java.time.Instant.parse(row.optString("at")))}
                            .getOrNull()
                        if(date!=null)Text(DateFormat.getDateTimeInstance(DateFormat.SHORT,DateFormat.SHORT)
                            .format(date),color=Color(0xFFAAAAAA),fontSize=10.sp)
                    }
                }
            }
            if(active.optString("status")!="closed"){
                OutlinedTextField(message,{message=it.take(4000)},
                    label={Text(local("Escribe un mensaje","Write a message"))},
                    modifier=Modifier.fillMaxWidth(),minLines=2,maxLines=6)
                Button(onClick={
                    scope.launch {
                        loading=true;error=null
                        try {
                            auth.sendSupportMessage(activeId,message)
                            message="";inbox=auth.supportInbox()
                        }catch(e:CancellationException){throw e}
                        catch(_:Exception){error=local("No se pudo enviar.","Unable to send.")}
                        finally{loading=false}
                    }
                },enabled=message.isNotBlank()&&!loading,modifier=Modifier.fillMaxWidth(),
                    colors=ButtonDefaults.buttonColors(containerColor=supportText,contentColor=Color.Black)){
                    Text(local("Enviar","Send"))
                }
            }
        }
        if(loading)LinearProgressIndicator(modifier=Modifier.fillMaxWidth(),color=supportAccent)
        if(error!=null)Text(error.orEmpty(),color=Color(0xFFFFBABA),fontSize=13.sp)
    }
}
