package com.ghostdeveloper.spdecode

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.AccountCircle
import androidx.compose.material.icons.outlined.Storefront
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch

/**
 * In-app account and store navigation. A commercial route cannot open
 * external web account pages. Auth and payments remain explicitly gated.
 */
@Suppress("UNUSED_PARAMETER")
@Composable
internal fun AccountDrawer(busy:Boolean,onExternalLink:(String)->Unit,
    onLegalLink:(String)->Unit={},
    content:@Composable (openMenu:()->Unit)->Unit) {
    val state=rememberDrawerState(DrawerValue.Closed)
    val scope=rememberCoroutineScope()
    var destination by rememberSaveable{mutableStateOf<String?>(null)}
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
                modifier=Modifier.widthIn(max=320.dp)){
                Column(Modifier.fillMaxWidth().padding(25.dp),
                    verticalArrangement=Arrangement.spacedBy(12.dp)){
                    Box(Modifier.size(64.dp).background(Color(0xFF242424),CircleShape),
                        contentAlignment=Alignment.Center){
                        Icon(Icons.Outlined.AccountCircle,null,Modifier.size(42.dp))
                    }
                    Text(stringResource(R.string.account_sign_in),
                        style=MaterialTheme.typography.titleLarge,
                        fontWeight=FontWeight.Bold)
                    Text(stringResource(R.string.account_web_description),
                        style=MaterialTheme.typography.bodySmall,
                        color=Color(0xFFABABAB))
                    Button(onClick={navigate("login")},enabled=!busy) {
                        Text(stringResource(R.string.account_sign_in))
                    }
                }
                HorizontalDivider(color=Color(0xFF292929))
                NavigationDrawerItem(selected=false,
                    label={Text(stringResource(R.string.account_my_account))},
                    icon={Icon(Icons.Outlined.AccountCircle,null)},
                    onClick={navigate("account")})
                NavigationDrawerItem(selected=false,
                    label={Text(stringResource(R.string.account_store))},
                    icon={Icon(Icons.Outlined.Storefront,null)},
                    onClick={navigate("store")})
            }
        }){
        val route=destination
        if(route==null)content {if(!busy)scope.launch{state.open()}}
        else NativeCommerceScreens(start=route,onExit={destination=null},
            onLegalLink=onLegalLink)
    }
}
