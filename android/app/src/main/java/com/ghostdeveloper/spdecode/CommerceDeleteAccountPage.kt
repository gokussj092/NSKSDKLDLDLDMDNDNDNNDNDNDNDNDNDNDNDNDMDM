package com.ghostdeveloper.spdecode

import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch

@Composable
internal fun CommerceDeleteAccountPage(language:String,auth:NativeCommerceAuth,
    onDeleted:()->Unit){
    val local:(String,String)->String={es,en->CommerceI18n.translate(language,es,en)}
    val context=LocalContext.current
    val scope=rememberCoroutineScope()
    val account=CommerceSession.user
    var confirmed by remember {mutableStateOf(false)}
    var password by remember {mutableStateOf("")}
    var busy by remember {mutableStateOf(false)}
    var error by remember {mutableStateOf<String?>(null)}
    val danger=Color(0xFFFF3030)
    Column(Modifier.fillMaxWidth(),horizontalAlignment=Alignment.CenterHorizontally,
        verticalArrangement=Arrangement.spacedBy(18.dp)){
        Spacer(Modifier.height(11.dp))
        Box(Modifier.size(90.dp)
            .background(Color(0xFF400B0B),RoundedCornerShape(28.dp))
            .border(BorderStroke(1.dp,Color(0xFFAD2020)),RoundedCornerShape(28.dp)),
            contentAlignment=Alignment.Center){
            Icon(Icons.Outlined.WarningAmber,null,tint=danger,modifier=Modifier.size(54.dp))
        }
        Text(local("Eliminar cuenta","Delete account"),color=Color.White,
            fontSize=29.sp,fontWeight=FontWeight.Bold,textAlign=TextAlign.Center,
            modifier=Modifier.fillMaxWidth())
        Text(local("Esta acción es permanente","This action is permanent"),
            color=danger,fontSize=14.sp,fontWeight=FontWeight.SemiBold,
            textAlign=TextAlign.Center,modifier=Modifier.fillMaxWidth())
        Column(Modifier.fillMaxWidth().background(Color(0xFF211B1B),RoundedCornerShape(23.dp))
            .border(BorderStroke(1.dp,Color(0xFF5F2323)),RoundedCornerShape(23.dp))
            .padding(19.dp),verticalArrangement=Arrangement.spacedBy(17.dp)){
            Text(local("Se eliminará tu perfil, las conversaciones de soporte y las sesiones. Tus accesos y licencias serán revocados. Las operaciones comerciales podrán conservar los registros contables exigidos por ley.",
                "Your profile, support messages and sessions will be deleted. Access and licenses will be revoked. Legally required purchase records may be retained."),
                color=Color(0xFFCCCCCC),fontSize=14.sp,lineHeight=20.sp)
            Row(verticalAlignment=Alignment.CenterVertically){
                Checkbox(checked=confirmed,onCheckedChange={confirmed=it},
                    colors=CheckboxDefaults.colors(checkedColor=danger,checkmarkColor=Color.White))
                Text(local("Confirmo que deseo eliminar permanentemente mi cuenta.",
                    "I confirm that I want to permanently delete my account."),
                    color=Color.White,fontSize=13.sp)
            }
            OutlinedTextField(password,{password=it.take(128)},modifier=Modifier.fillMaxWidth(),
                singleLine=true,visualTransformation=PasswordVisualTransformation(),
                label={Text(local("Contraseña de la cuenta","Account password"))})
            Button(modifier=Modifier.fillMaxWidth(),
                enabled=confirmed&&password.isNotEmpty()&&!busy,onClick={
                    scope.launch{
                        busy=true;error=null
                        try{
                            auth.deleteWithPassword(password)
                            password="";onDeleted()
                        }catch(e:CancellationException){throw e}
                        catch(_:Exception){error=local("La contraseña es incorrecta o no se pudo eliminar la cuenta.",
                            "Invalid password or account could not be deleted.")}
                        finally{busy=false}
                    }
                },colors=ButtonDefaults.buttonColors(containerColor=danger,
                    contentColor=Color.White,disabledContainerColor=Color(0xFF503030),
                    disabledContentColor=Color(0xFFBBBBBB))){
                Text(local("Eliminar con contraseña","Delete with password"))
            }
            if(NativeDeviceAccountGuard.enabled(context)&&
                NativeDeviceAccountGuard.supported(context)&&account!=null){
                OutlinedButton(modifier=Modifier.fillMaxWidth(),enabled=confirmed&&!busy,
                    onClick={
                        busy=true;error=null
                        val identity=account.id
                        scope.launch{
                            try{
                                val key=NativeDeviceAccountGuard.ensureDeviceKey(context,identity)
                                val challenge=auth.deletionChallenge(key)
                                NativeDeviceAccountGuard.authenticate(context,
                                    local("Confirmar eliminación","Confirm deletion")){ok->
                                    if(!ok){busy=false;return@authenticate}
                                    scope.launch{
                                        try{
                                            val sign=NativeDeviceAccountGuard.signedChallenge(context,
                                                identity,challenge.getString("challenge"))
                                            auth.deleteWithDevice(key,challenge,sign)
                                            onDeleted()
                                        }catch(_:Exception){
                                            error=local("No se pudo validar el dispositivo.",
                                                "Device verification failed.")
                                        }finally{busy=false}
                                    }
                                }
                            }catch(e:CancellationException){throw e}
                            catch(_:Exception){
                                error=local("Vincula primero la seguridad del dispositivo desde Seguridad.",
                                    "First link your device security under Security.")
                                busy=false
                            }
                        }
                    },colors=ButtonDefaults.outlinedButtonColors(contentColor=danger),
                    border=BorderStroke(1.dp,Color(0xFFB02B2B))){
                    Icon(Icons.Outlined.Fingerprint,null,tint=danger)
                    Spacer(Modifier.width(8.dp))
                    Text(local("Eliminar con huella o PIN","Delete with fingerprint or PIN"))
                }
            }
            if(account!=null)OutlinedButton(modifier=Modifier.fillMaxWidth(),
                enabled=confirmed&&!busy,onClick={
                    scope.launch{
                        busy=true;error=null
                        try{auth.deleteWithGoogle(account.id);onDeleted()}
                        catch(e:CancellationException){throw e}
                        catch(_:Exception){error=local("No se pudo verificar la cuenta de Google.",
                            "Google verification failed.")}
                        finally{busy=false}
                    }
                },colors=ButtonDefaults.outlinedButtonColors(contentColor=danger),
                border=BorderStroke(1.dp,Color(0xFFB02B2B))){
                Icon(Icons.Outlined.VerifiedUser,null,tint=danger)
                Spacer(Modifier.width(8.dp))
                Text(local("Confirmar con Google","Confirm with Google"))
            }
            if(error!=null)Text(error.orEmpty(),color=Color(0xFFFFBABA),fontSize=13.sp)
            if(busy)LinearProgressIndicator(modifier=Modifier.fillMaxWidth())
        }
    }
}
