package com.ghostdeveloper.spdecode

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.MailOutline
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/** The real packaged launcher resource is the identity on this screen. */
@Composable
internal fun CommerceAuthLanding(language:String,accepted:Boolean,
    busy:Boolean,error:String?,onAccepted:(Boolean)->Unit,
    onLegalLink:(String)->Unit,onGoogle:()->Unit,onEmail:()->Unit){
    val t:(String,String)->String={es,en->CommerceI18n.translate(language,es,en)}
    val bg=Color(0xFF222222)
    val selected=Color(0xFFF7F7F7)
    val secondary=Color(0xFFB3B3B3)
    var mode by rememberSaveable{mutableIntStateOf(0)}
    Column(Modifier.fillMaxWidth().padding(top=10.dp,bottom=25.dp),
        horizontalAlignment=Alignment.CenterHorizontally,
        verticalArrangement=Arrangement.spacedBy(14.dp)){
        Box(Modifier.size(100.dp)
            .background(bg,RoundedCornerShape(27.dp))
            .border(1.dp,Color(0xFF484848),RoundedCornerShape(27.dp)),
            contentAlignment=Alignment.Center){
            Image(painterResource(id=R.mipmap.ic_launcher),
                contentDescription="SP-DECODE",
                modifier=Modifier.size(82.dp))
        }
        Text("SP-DECODE",color=selected,fontSize=21.sp,fontWeight=FontWeight.Bold)
        Text(if(mode==0)t("Bienvenido de nuevo","Welcome back")
                 else t("Crea tu cuenta","Create your account"),
            color=selected,fontSize=29.sp,fontWeight=FontWeight.Bold,
            textAlign=TextAlign.Center)
        Text(if(mode==0)t("Inicia sesión para continuar",
                "Sign in to continue")
             else t("Únete a SP-DECODE con tu cuenta de Google",
                "Join SP-DECODE with your Google account"),
            color=secondary,fontSize=14.sp,textAlign=TextAlign.Center)
        Spacer(Modifier.height(10.dp))
        Column(Modifier.fillMaxWidth()
            .background(bg,RoundedCornerShape(25.dp)).padding(18.dp),
            verticalArrangement=Arrangement.spacedBy(17.dp)){
            Row(Modifier.fillMaxWidth()
                .background(Color(0xFF151515),RoundedCornerShape(18.dp)).padding(4.dp),
                horizontalArrangement=Arrangement.spacedBy(5.dp)){
                listOf(t("Iniciar sesión","Sign in"),
                    t("Crear cuenta","Create account")).forEachIndexed{index,label->
                    Box(Modifier.weight(1f)
                        .clip(RoundedCornerShape(14.dp))
                        .background(if(mode==index)selected else Color.Transparent)
                        .clickable(enabled=!busy){mode=index}
                        .padding(vertical=14.dp),
                        contentAlignment=Alignment.Center){
                        Text(label,color=if(mode==index)Color.Black else secondary,
                            fontWeight=FontWeight.SemiBold,fontSize=13.sp,
                            textAlign=TextAlign.Center,maxLines=1)
                    }
                }
            }
            Text(if(mode==0)t("Accede a tu cuenta","Acceso a tu cuenta")
                   else t("Registrarse con Google","Create with Google"),
                color=selected,fontWeight=FontWeight.SemiBold,fontSize=17.sp)
            OutlinedButton(onClick=onGoogle,enabled=accepted&&!busy,
                modifier=Modifier.fillMaxWidth().heightIn(min=53.dp),
                shape=RoundedCornerShape(16.dp),
                border=androidx.compose.foundation.BorderStroke(1.dp,Color(0xFF686868))){
                Box(Modifier.size(28.dp).background(Color.White,RoundedCornerShape(50)),
                    contentAlignment=Alignment.Center){
                    Text("G",color=Color(0xFF4285F4),fontSize=19.sp,
                        fontWeight=FontWeight.Bold)
                }
                Spacer(Modifier.width(11.dp))
                Text(if(mode==0)t("Continuar con Google","Continue with Google")
                     else t("Crear cuenta con Google","Create account with Google"),
                    color=selected,fontWeight=FontWeight.Medium)
            }
            if(mode==0){
                Row(Modifier.fillMaxWidth(),verticalAlignment=Alignment.CenterVertically,
                    horizontalArrangement=Arrangement.spacedBy(11.dp)){
                    HorizontalDivider(modifier=Modifier.weight(1f),color=Color(0xFF515151))
                    Text(t("o con correo","or with email"),color=secondary,fontSize=12.sp)
                    HorizontalDivider(modifier=Modifier.weight(1f),color=Color(0xFF515151))
                }
                OutlinedButton(onClick=onEmail,enabled=!busy,
                    modifier=Modifier.fillMaxWidth().heightIn(min=53.dp),
                    shape=RoundedCornerShape(16.dp),
                    border=androidx.compose.foundation.BorderStroke(1.dp,Color(0xFF686868))){
                    Icon(Icons.Outlined.MailOutline,null,tint=selected)
                    Spacer(Modifier.width(11.dp))
                    Text(t("Correo y contraseña","Email and password"),color=selected,
                        fontWeight=FontWeight.Medium)
                }
            }
            CommerceConsentRow(language,accepted,onAccepted,onLegalLink)
            if(busy)LinearProgressIndicator(modifier=Modifier.fillMaxWidth(),
                color=Color(0xFFB8DCC0))
            if(error!=null)Text(error,color=Color(0xFFFF7777),
                fontSize=12.sp,lineHeight=18.sp)
        }
        Text(t("Tu cuenta y compras están vinculadas de forma segura.",
            "Your account and purchases are securely linked."),
            color=secondary,fontSize=12.sp,textAlign=TextAlign.Center)
    }
}
