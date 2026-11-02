package com.ghostdeveloper.spdecode

import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/** Explicit allowlisted destinations. Never derive external URLs from user content. */
internal object AboutOfficialLinks {
    const val WEBSITE="https://spdecode.xyz"
    const val CHANNEL="https://t.me/GhostDeve"
    const val COMMUNITY="https://t.me/+Ntu6EJMirrAwMzgx"
    const val CONTACT="https://t.me/Gh0stDeveloper"
}

private val AboutSurface=Color(0xFF242424)
private val AboutWhite=Color(0xFFF7F7F7)
private val AboutMuted=Color(0xFFABABAB)
private val AboutDivider=Color(0xFF383838)

/** Phase 6: the approved first AMOLED design; no network calls on screen open. */
@Composable
fun AboutScreen(
    onBack:()->Unit,
    onExternalLink:(String)->Unit,
    onLegalLink:(String)->Unit,
    cloudEnabled:Boolean=BuildConfig.SPDECODE_CLOUD_ENABLED,
){
    Column(Modifier.fillMaxSize().background(Color.Black).testTag("about_screen")) {
        Row(Modifier.fillMaxWidth().padding(horizontal=12.dp,vertical=8.dp),
            verticalAlignment=Alignment.CenterVertically) {
            IconButton(onClick=onBack,modifier=Modifier.testTag("about_back")) {
                Icon(Icons.Outlined.ArrowBack,stringResource(R.string.settings),tint=AboutWhite)
            }
            Text(stringResource(R.string.about_title),fontSize=22.sp,
                fontWeight=FontWeight.Bold,color=AboutWhite)
        }
        Column(
            Modifier.fillMaxSize().verticalScroll(rememberScrollState())
                .padding(horizontal=20.dp,vertical=12.dp),
            verticalArrangement=Arrangement.spacedBy(14.dp),
            horizontalAlignment=Alignment.CenterHorizontally,
        ){
            Image(
                painter=painterResource(R.drawable.ic_launcher_foreground),
                contentDescription=stringResource(R.string.app_name),
                modifier=Modifier.size(78.dp)
                    .background(AboutSurface,RoundedCornerShape(20.dp))
                    .padding(8.dp),
            )
            Text(stringResource(R.string.app_name),fontSize=26.sp,
                fontWeight=FontWeight.Bold,color=AboutWhite)
            Text(stringResource(R.string.about_screen_description),
                fontSize=13.sp,lineHeight=19.sp,color=AboutMuted,
                textAlign=TextAlign.Center)
            Surface(color=AboutSurface,shape=RoundedCornerShape(50)) {
                Text(
                    stringResource(R.string.about_screen_version_badge,
                        BuildConfig.VERSION_NAME,BuildConfig.VERSION_CODE),
                    modifier=Modifier.padding(horizontal=14.dp,vertical=8.dp),
                    color=AboutWhite,fontSize=12.sp,
                )
            }
            AboutSection(Icons.Outlined.Info,stringResource(R.string.about_screen_info)) {
                AboutInfoRow(stringResource(R.string.developer_credits),"Ghost Developer")
                AboutInfoRow(
                    stringResource(R.string.about_screen_languages),
                    SupportedLanguages.options.count{it.tag!="system"}.toString(),
                )
                AboutInfoRow(stringResource(R.string.about_screen_installed),
                    BuildConfig.VERSION_NAME)
            }
            AboutSection(Icons.Outlined.Widgets,stringResource(R.string.about_screen_features)) {
                AboutFeature(Icons.Outlined.Description,
                    stringResource(R.string.about_screen_feature_decode))
                AboutFeature(Icons.Outlined.Cloud,
                    stringResource(R.string.about_screen_feature_catalog))
                AboutFeature(Icons.Outlined.FileUpload,
                    stringResource(R.string.about_screen_feature_export))
                AboutFeature(Icons.Outlined.History,
                    stringResource(R.string.about_screen_feature_history))
            }
            AboutSection(Icons.Outlined.Shield,stringResource(R.string.about_screen_security)) {
                Text(
                    stringResource(
                        if(cloudEnabled) R.string.about_screen_cloud_security
                        else R.string.about_screen_local_security
                    ),
                    color=AboutMuted,fontSize=13.sp,lineHeight=19.sp,
                )
                if(cloudEnabled){
                    AboutActionRow(
                        Icons.Outlined.PrivacyTip,
                        stringResource(R.string.about_screen_privacy),
                        "about_privacy",
                    ){onLegalLink("privacy")}
                    AboutActionRow(
                        Icons.Outlined.Gavel,
                        stringResource(R.string.about_screen_terms),
                        "about_terms",
                    ){onLegalLink("terms")}
                }
            }
            AboutSection(Icons.Outlined.Language,stringResource(R.string.about_screen_links)) {
                AboutActionRow(Icons.Outlined.Public,
                    stringResource(R.string.about_screen_website),
                    "about_website","spdecode.xyz",AboutOfficialLinks.WEBSITE,
                    onExternalLink)
                AboutActionRow(Icons.Outlined.Campaign,
                    stringResource(R.string.telegram_channel),
                    "about_channel","@GhostDeve",AboutOfficialLinks.CHANNEL,
                    onExternalLink)
                AboutActionRow(Icons.Outlined.Groups,
                    stringResource(R.string.telegram_group),
                    "about_community",stringResource(R.string.about_screen_community_detail),
                    AboutOfficialLinks.COMMUNITY,onExternalLink)
                AboutActionRow(Icons.Outlined.PersonOutline,
                    stringResource(R.string.contact_developer),
                    "about_contact","@Gh0stDeveloper",AboutOfficialLinks.CONTACT,
                    onExternalLink)
            }
            Text(stringResource(R.string.about_screen_credit),
                fontSize=12.sp,color=AboutMuted,textAlign=TextAlign.Center)
            Text(stringResource(R.string.about_screen_copyright),
                fontSize=11.sp,color=AboutMuted,textAlign=TextAlign.Center)
            Spacer(Modifier.height(8.dp))
        }
    }
}

@Composable
private fun AboutSection(
    icon:androidx.compose.ui.graphics.vector.ImageVector,
    title:String,
    content:@Composable ColumnScope.()->Unit,
){
    Surface(
        modifier=Modifier.fillMaxWidth(),
        color=AboutSurface,shape=RoundedCornerShape(16.dp),
    ){
        Column(Modifier.padding(16.dp),verticalArrangement=Arrangement.spacedBy(11.dp)){
            Row(verticalAlignment=Alignment.CenterVertically) {
                Icon(icon,null,tint=AboutWhite,modifier=Modifier.size(23.dp))
                Spacer(Modifier.width(11.dp))
                Text(title,color=AboutWhite,fontSize=16.sp,fontWeight=FontWeight.SemiBold)
            }
            content()
        }
    }
}
@Composable private fun AboutInfoRow(title:String,value:String){
    Row(Modifier.fillMaxWidth(),horizontalArrangement=Arrangement.SpaceBetween,
        verticalAlignment=Alignment.CenterVertically){
        Text(title,color=AboutMuted,fontSize=13.sp,modifier=Modifier.weight(1f))
        Spacer(Modifier.width(10.dp))
        Text(value,color=AboutWhite,fontSize=13.sp,fontWeight=FontWeight.Medium)
    }
}
@Composable private fun AboutFeature(
    icon:androidx.compose.ui.graphics.vector.ImageVector,label:String,
){
    Row(Modifier.fillMaxWidth(),verticalAlignment=Alignment.CenterVertically) {
        Icon(icon,null,tint=AboutMuted,modifier=Modifier.size(19.dp))
        Spacer(Modifier.width(10.dp))
        Text(label,color=AboutWhite,fontSize=13.sp)
    }
}
@Composable private fun AboutActionRow(
    icon:androidx.compose.ui.graphics.vector.ImageVector,
    label:String,tag:String,detail:String,url:String,onExternalLink:(String)->Unit,
){
    AboutActionRow(icon,label,tag,detail){onExternalLink(url)}
}
@Composable private fun AboutActionRow(
    icon:androidx.compose.ui.graphics.vector.ImageVector,
    label:String,tag:String,detail:String?=null,onClick:()->Unit,
){
    Column {
        Spacer(Modifier.fillMaxWidth().height(1.dp).background(AboutDivider))
        Row(Modifier.fillMaxWidth().testTag(tag).clickable(onClick=onClick)
            .padding(vertical=8.dp),verticalAlignment=Alignment.CenterVertically){
            Icon(icon,null,tint=AboutMuted,modifier=Modifier.size(20.dp))
            Spacer(Modifier.width(10.dp))
            Column(Modifier.weight(1f),verticalArrangement=Arrangement.spacedBy(3.dp)) {
                Text(label,color=AboutWhite,fontSize=13.sp,fontWeight=FontWeight.Medium)
                if(detail!=null)Text(detail,color=AboutMuted,fontSize=11.sp)
            }
            Icon(Icons.Outlined.ChevronRight,null,tint=AboutMuted,
                modifier=Modifier.size(19.dp))
        }
    }
}
