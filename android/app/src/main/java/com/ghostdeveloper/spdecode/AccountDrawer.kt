package com.ghostdeveloper.spdecode

import androidx.activity.compose.BackHandler
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.AccountCircle
import androidx.compose.material.icons.outlined.OpenInNew
import androidx.compose.material.icons.outlined.Storefront
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.launch

/** Web account access only. Never invent an authenticated native profile. */
@Composable
internal fun AccountDrawer(busy:Boolean,onExternalLink:(String)->Unit,
    content:@Composable (openMenu:()->Unit)->Unit) {
    val state=rememberDrawerState(DrawerValue.Closed)
    val scope=rememberCoroutineScope()
    BackHandler(state.isOpen){scope.launch{state.close()}}
    ModalNavigationDrawer(drawerState=state,gesturesEnabled=!busy,
        drawerContent={ModalDrawerSheet(drawerContainerColor=Color.Black,
            drawerContentColor=Color(0xFFF7F7F7),modifier=Modifier.widthIn(max=320.dp)) {
            Column(Modifier.fillMaxWidth().padding(25.dp),verticalArrangement=Arrangement.spacedBy(12.dp)) {
                Box(Modifier.size(64.dp).background(Color(0xFF242424),CircleShape),contentAlignment=Alignment.Center) {
                    Icon(Icons.Outlined.AccountCircle,null,Modifier.size(42.dp))
                }
                Text(stringResource(R.string.account_sign_in),style=MaterialTheme.typography.titleLarge,fontWeight=FontWeight.Bold)
                Text(stringResource(if(BuildConfig.SPDECODE_PLAY_UPDATES)R.string.apk_analysis_coming_soon
                    else R.string.account_web_description),style=MaterialTheme.typography.bodySmall,color=Color(0xFFABABAB))
                Button(enabled=!BuildConfig.SPDECODE_PLAY_UPDATES,onClick={scope.launch{state.close()};onExternalLink("https://spdecode.xyz/account")}) {
                    Text(stringResource(R.string.account_continue_web))
                }
            }
            HorizontalDivider(color=Color(0xFF292929))
            if(!BuildConfig.SPDECODE_PLAY_UPDATES)NavigationDrawerItem(selected=false,label={Text(stringResource(R.string.account_my_account))},
                icon={Icon(Icons.Outlined.OpenInNew,null)},onClick={scope.launch{state.close()};onExternalLink("https://spdecode.xyz/account")})
            if(!BuildConfig.SPDECODE_PLAY_UPDATES)NavigationDrawerItem(selected=false,
                label={Text(stringResource(R.string.account_store))},icon={Icon(Icons.Outlined.Storefront,null)},
                onClick={scope.launch{state.close()};onExternalLink("https://spdecode.xyz/store")})
        }}) {
        content {if(!busy)scope.launch{state.open()}}
    }
}
