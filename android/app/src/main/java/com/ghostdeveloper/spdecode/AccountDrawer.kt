package com.ghostdeveloper.spdecode

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.AccountCircle
import androidx.compose.material.icons.outlined.ArrowBack
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
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.launch

/**
 * Account/store navigation remains native. Until authentication and purchase
 * verification are implemented, never open a browser, claim a logged-in user
 * or offer a nonfunctional checkout.
 */
@Suppress("UNUSED_PARAMETER")
@Composable
internal fun AccountDrawer(busy:Boolean,onExternalLink:(String)->Unit,
    content:@Composable (openMenu:()->Unit)->Unit) {
    val state=rememberDrawerState(DrawerValue.Closed)
    val scope=rememberCoroutineScope()
    var destination by rememberSaveable { mutableStateOf<String?>(null) }
    BackHandler(enabled=state.isOpen && destination==null) { scope.launch {state.close()} }
    BackHandler(enabled=destination!=null) { destination=null }
    fun openDestination(where:String) {
        scope.launch {state.close()}
        destination=where
    }
    ModalNavigationDrawer(
        drawerState=state,
        gesturesEnabled=!busy && destination==null,
        drawerContent={
            ModalDrawerSheet(
                drawerContainerColor=Color.Black,
                drawerContentColor=Color(0xFFF7F7F7),
                modifier=Modifier.widthIn(max=320.dp),
            ) {
                Column(
                    Modifier.fillMaxWidth().padding(25.dp),
                    verticalArrangement=Arrangement.spacedBy(12.dp),
                ) {
                    Box(
                        Modifier.size(64.dp).background(Color(0xFF242424),CircleShape),
                        contentAlignment=Alignment.Center,
                    ) {
                        Icon(Icons.Outlined.AccountCircle,null,Modifier.size(42.dp))
                    }
                    Text(
                        stringResource(R.string.account_sign_in),
                        style=MaterialTheme.typography.titleLarge,
                        fontWeight=FontWeight.Bold,
                    )
                    Text(
                        stringResource(R.string.apk_analysis_coming_soon),
                        style=MaterialTheme.typography.bodySmall,
                        color=Color(0xFFABABAB),
                    )
                    Button(
                        enabled=!busy,
                        onClick={openDestination("account")},
                    ) { Text(stringResource(R.string.account_my_account)) }
                }
                HorizontalDivider(color=Color(0xFF292929))
                NavigationDrawerItem(
                    selected=false,
                    label={Text(stringResource(R.string.account_my_account))},
                    icon={Icon(Icons.Outlined.AccountCircle,null)},
                    onClick={openDestination("account")},
                )
                NavigationDrawerItem(
                    selected=false,
                    label={Text(stringResource(R.string.account_store))},
                    icon={Icon(Icons.Outlined.Storefront,null)},
                    onClick={openDestination("store")},
                )
            }
        },
    ) {
        if(destination==null) {
            content { if(!busy)scope.launch {state.open()} }
        } else {
            val store=destination=="store"
            Column(
                Modifier.fillMaxSize().background(Color.Black)
                    .safeDrawingPadding()
                    .padding(horizontal=20.dp, vertical=14.dp),
                verticalArrangement=Arrangement.spacedBy(15.dp),
            ) {
                Row(verticalAlignment=Alignment.CenterVertically) {
                    IconButton(onClick={destination=null}) {
                        Icon(Icons.Outlined.ArrowBack,null,tint=Color.White)
                    }
                    Spacer(Modifier.width(8.dp))
                    Text(
                        stringResource(if(store)R.string.account_store else R.string.account_my_account),
                        color=Color.White,
                        fontSize=22.sp,
                        fontWeight=FontWeight.Bold,
                    )
                }
                Box(Modifier.fillMaxWidth().weight(1f),contentAlignment=Alignment.Center) {
                    Column(
                        horizontalAlignment=Alignment.CenterHorizontally,
                        verticalArrangement=Arrangement.spacedBy(14.dp),
                    ) {
                        Surface(
                            color=Color(0xFF242424),
                            shape=RoundedCornerShape(20.dp),
                        ) {
                            Icon(
                                if(store)Icons.Outlined.Storefront else Icons.Outlined.AccountCircle,
                                contentDescription=null,
                                tint=Color.White,
                                modifier=Modifier.padding(22.dp).size(42.dp),
                            )
                        }
                        Text(
                            stringResource(R.string.apk_analysis_coming_soon),
                            color=Color.White,
                            fontWeight=FontWeight.Bold,
                            style=MaterialTheme.typography.headlineSmall,
                        )
                    }
                }
            }
        }
    }
}
