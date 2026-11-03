package com.ghostdeveloper.spdecode

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Android
import androidx.compose.material.icons.outlined.CreditCard
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

// Cloud-only placeholder: no APK picker, client-side analysis, billing, or balance API.
private val previewCard=Color(0xFF242424)
private val previewText=Color(0xFFF7F7F7)
private val previewMuted=Color(0xFFABABAB)
private val previewBorder=Color(0xFF383838)

@Composable
internal fun ApkAnalysisComingSoonScreen() {
    Column(
        modifier=Modifier.fillMaxSize().testTag("apk_analysis_placeholder")
            .padding(horizontal=20.dp,vertical=16.dp),
        verticalArrangement=Arrangement.spacedBy(16.dp),
    ) {
        Text(stringResource(R.string.apk_analysis_title),
            color=previewText,fontSize=24.sp,fontWeight=FontWeight.Bold)
        // Disabled intentionally: the service is not yet enabled, and no APK is read or uploaded.
        OutlinedButton(
            onClick={},enabled=false,
            modifier=Modifier.fillMaxWidth().testTag("apk_analysis_import_disabled"),
            shape=RoundedCornerShape(13.dp),
        ) {
            Icon(Icons.Outlined.Description,null)
            Spacer(Modifier.width(8.dp))
            Text(stringResource(R.string.apk_import_button))
        }
        Box(Modifier.fillMaxWidth().weight(1f),
            contentAlignment=Alignment.Center) {
            Column(
                Modifier.padding(horizontal=16.dp),
                horizontalAlignment=Alignment.CenterHorizontally,
                verticalArrangement=Arrangement.spacedBy(15.dp),
            ) {
                Surface(color=previewCard,shape=RoundedCornerShape(18.dp),
                    border=BorderStroke(1.dp,previewBorder)) {
                    Icon(Icons.Outlined.Android,null,tint=previewText,
                        modifier=Modifier.padding(18.dp).size(34.dp))
                }
                Text(stringResource(R.string.apk_analysis_coming_soon),
                    color=previewText,fontWeight=FontWeight.Bold,
                    fontSize=25.sp,textAlign=TextAlign.Center)
                Text(stringResource(R.string.apk_future_message),
                    color=previewMuted,fontSize=14.sp,lineHeight=21.sp,
                    textAlign=TextAlign.Center)
            }
        }
    }
}

@Composable
internal fun ApkCreditsComingSoonScreen() {
    Column(
        modifier=Modifier.fillMaxSize().testTag("apk_credits_screen")
            .padding(horizontal=20.dp,vertical=16.dp),
        verticalArrangement=Arrangement.spacedBy(15.dp),
    ) {
        Text(stringResource(R.string.apk_credits_title),color=previewText,
            fontSize=24.sp,fontWeight=FontWeight.Bold)
        Text(stringResource(R.string.apk_credits_intro),
            color=previewMuted,fontSize=13.sp,lineHeight=19.sp)
        Surface(
            color=previewCard,shape=RoundedCornerShape(18.dp),
            border=BorderStroke(1.dp,previewBorder),
            modifier=Modifier.fillMaxWidth(),
        ) {
            Column(Modifier.padding(22.dp),
                horizontalAlignment=Alignment.CenterHorizontally,
                verticalArrangement=Arrangement.spacedBy(12.dp)) {
                Icon(Icons.Outlined.CreditCard,null,tint=previewText,
                    modifier=Modifier.size(34.dp))
                Text(stringResource(R.string.apk_credits_title),color=previewText,
                    fontWeight=FontWeight.Bold,fontSize=20.sp)
                CreditSoonBadge()
                Text(stringResource(R.string.apk_credits_notice),
                    color=previewMuted,fontSize=13.sp,lineHeight=19.sp,
                    textAlign=TextAlign.Center)
            }
        }
        Surface(
            color=previewCard,shape=RoundedCornerShape(18.dp),
            border=BorderStroke(1.dp,previewBorder),
            modifier=Modifier.fillMaxWidth().testTag("apk_credits_buy"),
        ) {
            Column(Modifier.padding(17.dp),
                verticalArrangement=Arrangement.spacedBy(12.dp)) {
                Text(stringResource(R.string.apk_credits_buy_title),
                    color=previewText,fontWeight=FontWeight.SemiBold,fontSize=17.sp)
                CreditPriceLine(R.string.apk_credits_one)
                OutlinedButton(onClick={},enabled=false,
                    modifier=Modifier.fillMaxWidth().testTag("apk_buy_one_disabled"),
                    shape=RoundedCornerShape(12.dp)) {
                    Text(stringResource(R.string.apk_credits_buy_one))
                }
                HorizontalDivider(color=previewBorder)
                CreditPriceLine(R.string.apk_credits_packages)
                OutlinedButton(onClick={},enabled=false,
                    modifier=Modifier.fillMaxWidth().testTag("apk_buy_bundle_disabled"),
                    shape=RoundedCornerShape(12.dp)) {
                    Text(stringResource(R.string.apk_credits_buy_package))
                }
            }
        }
        Surface(
            color=previewCard,shape=RoundedCornerShape(18.dp),
            border=BorderStroke(1.dp,previewBorder),
            modifier=Modifier.fillMaxWidth().testTag("apk_credits_prices"),
        ) {
            Column(Modifier.padding(17.dp),
                verticalArrangement=Arrangement.spacedBy(13.dp)) {
                Text(stringResource(R.string.apk_credits_prices_title),
                    color=previewText,fontWeight=FontWeight.SemiBold,fontSize=17.sp)
                CreditPriceLine(R.string.apk_credits_prices_title)
                CreditPriceLine(R.string.apk_credits_subscriptions)
            }
        }
        // No "1 APK = 1 credit" or proposed USD pricing on this screen.
        // Balance, purchases, payments and subscriptions remain unavailable.
    }
}

@Composable
private fun CreditPriceLine(label:Int) {
    Row(Modifier.fillMaxWidth(),verticalAlignment=Alignment.CenterVertically,
        horizontalArrangement=Arrangement.spacedBy(12.dp)) {
        Text(stringResource(label),color=previewMuted,fontSize=13.sp,
            modifier=Modifier.weight(1f))
        CreditSoonBadge()
    }
}

@Composable
private fun CreditSoonBadge() {
    Surface(color=Color(0xFF333333),shape=RoundedCornerShape(20.dp),
        border=BorderStroke(1.dp,previewBorder)) {
        Text(stringResource(R.string.apk_analysis_coming_soon),
            color=previewText,fontWeight=FontWeight.SemiBold,fontSize=11.sp,
            modifier=Modifier.padding(horizontal=10.dp,vertical=5.dp))
    }
}
