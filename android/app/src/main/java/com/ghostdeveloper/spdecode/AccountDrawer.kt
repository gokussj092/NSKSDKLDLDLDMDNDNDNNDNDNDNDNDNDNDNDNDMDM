package com.ghostdeveloper.spdecode

import androidx.activity.compose.BackHandler
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
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch

/** Reusable profile state powers both drawer and account; no tokens in Compose state. */
@Suppress("UNUSED_PARAMETER")
@Composable
internal fun AccountDrawer(busy:Boolean,onExternalLink:(String)->Unit,
    onLegalLink:(String)->Unit={},
    onCheckoutUrl:(String)->Unit={},
    content:@Composable (openMenu:()->Unit)->Unit) {
    val state=rememberDrawerState(DrawerValue.Closed)
    val scope=rememberCoroutineScope()
    val context=LocalContext.current
    val language=context.resources.configuration.locales[0].language
    val local:(String,String)->String={es,en->CommerceI18n.translate(language,es,en)}
    val auth=remember(context){NativeCommerceAuth(context)}
    val user=CommerceSession.user
    var destination by remember {mutableStateOf<String?>(null)}
    LaunchedEffect(Unit) {
        auth.restoreCachedIdentity()
        if(auth.sessionToken()!=null)runCatching{auth.account()}
    }
    BackHandler(state.isOpen && destination==null){scope.launch{state.close()}}
    fun navigate(route:String) {
        if(busy)return
        destination=route
        scope.launch{state.close()}
    }
    ModalNavigationDrawer(drawerState=state,gesturesEnabled=!busy && destination==null,
        drawerContent={
            ModalDrawerSheet(drawerContainerColor=Color.Black,
                drawerContentColor=Color(0xFFF7F7F7),
                modifier=Modifier.widthIn(max=340.dp)){
                Column(Modifier.fillMaxWidth().padding(24.dp),
                    verticalArrangement=Arrangement.spacedBy(12.dp)){
                    Row(verticalAlignment=Alignment.CenterVertically,
                        horizontalArrangement=Arrangement.spacedBy(13.dp)){
                        CommerceAvatar(user?.avatar,Modifier.size(70.dp))
                        Column(Modifier.weight(1f),verticalArrangement=Arrangement.spacedBy(5.dp)){
                            Text(user?.name?.takeIf{it.isNotBlank()}
                                ?:local("Iniciar sesión","Sign in"),
                                fontSize=20.sp,fontWeight=FontWeight.Bold,maxLines=2)
                            if(user!=null){
                                Text("@"+user.username,color=Color(0xFFB8DCC0),fontSize=13.sp)
                            }else Text(local("Accede a tu cuenta desde la aplicación",
                                "Access your account inside the app"),
                                color=Color(0xFFAAAAAA),fontSize=12.sp)
                        }
                    }
                    if(user!=null){
                        Surface(color=Color(0xFF232D27),shape=RoundedCornerShape(12.dp)){
                            Text(local("Cuenta vinculada a Google","Google-linked account"),
                                color=Color(0xFFB8DCC0),fontSize=12.sp,
                                modifier=Modifier.padding(horizontal=13.dp,vertical=8.dp))
                        }
                        OutlinedButton(onClick={navigate("profile-edit")},
                            modifier=Modifier.fillMaxWidth()){
                            Icon(Icons.Outlined.Edit,null)
                            Spacer(Modifier.width(8.dp))
                            Text(CommerceProfileText.get(language,"Edit profile"))
                        }
                    }else Button(onClick={navigate("login")},enabled=!busy,
                        modifier=Modifier.fillMaxWidth(),
                        colors=ButtonDefaults.buttonColors(containerColor=Color.White,
                            contentColor=Color.Black)){
                        Text(local("Iniciar sesión","Sign in"))
                    }
                }
                HorizontalDivider(color=Color(0xFF292929))
                NavigationDrawerItem(selected=false,
                    label={Text(local("Mi cuenta","My account"))},
                    icon={Icon(Icons.Outlined.AccountCircle,null)},
                    onClick={navigate("account")})
                NavigationDrawerItem(selected=false,
                    label={Text(local("Tienda","Store"))},
                    icon={Icon(Icons.Outlined.Storefront,null)},
                    onClick={navigate("store")})
                if(user!=null) {
                    NavigationDrawerItem(selected=false,label={Text(local("Compras","Orders"))},
                        icon={Icon(Icons.Outlined.ReceiptLong,null)},onClick={navigate("orders")})
                    NavigationDrawerItem(selected=false,label={Text("API")},
                        icon={Icon(Icons.Outlined.Key,null)},onClick={navigate("api")})
                    NavigationDrawerItem(selected=false,label={Text(local("Seguridad","Security"))},
                        icon={Icon(Icons.Outlined.Security,null)},onClick={navigate("security")})
                    HorizontalDivider(color=Color(0xFF292929))
                    NavigationDrawerItem(selected=false,label={Text(local("Cerrar sesión","Sign out"))},
                        icon={Icon(Icons.Outlined.Logout,null)},
                        onClick={
                            if(!busy) scope.launch {
                                runCatching{auth.signOut()}
                                destination="login"
                                state.close()
                            }
                        })
                }
            }
        }){
        val route=destination
        if(route==null)content {if(!busy)scope.launch{state.open()}}
        else NativeCommerceScreens(start=route,onExit={destination=null},
            onLegalLink=onLegalLink,onCheckoutUrl=onCheckoutUrl)
    }
}
