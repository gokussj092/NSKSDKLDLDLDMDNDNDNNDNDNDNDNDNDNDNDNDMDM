package com.ghostdeveloper.spdecode

import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Android
import androidx.compose.material.icons.outlined.Description
import androidx.compose.material.icons.outlined.Info
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

// Phase 2 is a purely informative preview. Do not add file pickers, network
// calls, account or credit logic here before the paid service is approved.
private val PreviewCard = Color(0xFF242424)
private val PreviewText = Color(0xFFF7F7F7)
private val PreviewMuted = Color(0xFFABABAB)
private val PreviewBorder = Color(0xFF383838)

@Composable
internal fun ApkAnalysisComingSoonScreen() {
    Column(
        modifier = Modifier.fillMaxSize().testTag("apk_analysis_placeholder")
            .verticalScroll(rememberScrollState())
            .padding(horizontal = 20.dp, vertical = 16.dp),
        verticalArrangement = Arrangement.spacedBy(16.dp),
    ) {
        Row(verticalAlignment = Alignment.CenterVertically) {
            Text(
                text = stringResource(R.string.apk_analysis_title),
                modifier = Modifier.weight(1f),
                color = PreviewText,
                fontSize = 24.sp,
                fontWeight = FontWeight.Bold,
            )
            Surface(
                color = PreviewCard,
                shape = RoundedCornerShape(30.dp),
                border = BorderStroke(1.dp, PreviewBorder),
            ) {
                Text(
                    stringResource(R.string.apk_analysis_coming_soon),
                    modifier = Modifier.padding(horizontal = 12.dp, vertical = 7.dp),
                    color = PreviewText,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 11.sp,
                )
            }
        }

        Surface(
            color = PreviewCard,
            shape = RoundedCornerShape(18.dp),
            border = BorderStroke(1.dp, PreviewBorder),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(
                modifier = Modifier.padding(20.dp),
                verticalArrangement = Arrangement.spacedBy(12.dp),
            ) {
                Surface(
                    color = Color(0xFF353535),
                    shape = RoundedCornerShape(16.dp),
                ) {
                    Icon(
                        Icons.Outlined.Android,
                        contentDescription = null,
                        tint = PreviewText,
                        modifier = Modifier.padding(14.dp).size(34.dp),
                    )
                }
                Text(
                    stringResource(R.string.apk_analysis_intro_title),
                    color = PreviewText,
                    fontSize = 19.sp,
                    fontWeight = FontWeight.SemiBold,
                )
                Text(
                    stringResource(R.string.apk_analysis_intro_detail),
                    color = PreviewMuted,
                    fontSize = 14.sp,
                    lineHeight = 21.sp,
                )
            }
        }

        Text(
            stringResource(R.string.apk_analysis_steps_title),
            color = PreviewText,
            fontSize = 17.sp,
            fontWeight = FontWeight.SemiBold,
        )
        Surface(
            color = PreviewCard,
            shape = RoundedCornerShape(16.dp),
            modifier = Modifier.fillMaxWidth(),
        ) {
            Column(Modifier.padding(horizontal = 16.dp, vertical = 8.dp)) {
                PreviewStep("01", R.string.apk_analysis_step_import)
                HorizontalDivider(color = PreviewBorder)
                PreviewStep("02", R.string.apk_analysis_step_inspect)
                HorizontalDivider(color = PreviewBorder)
                PreviewStep("03", R.string.apk_analysis_step_report)
            }
        }

        Surface(
            color = PreviewCard,
            shape = RoundedCornerShape(16.dp),
            border = BorderStroke(1.dp, PreviewBorder),
            modifier = Modifier.fillMaxWidth().testTag("apk_analysis_pricing"),
        ) {
            Column(
                modifier = Modifier.padding(18.dp),
                verticalArrangement = Arrangement.spacedBy(11.dp),
            ) {
                Text(
                    stringResource(R.string.apk_analysis_subscription_title),
                    color = PreviewText,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 17.sp,
                )
                Text(
                    stringResource(R.string.apk_analysis_subscription_detail),
                    color = PreviewMuted,
                    fontSize = 13.sp,
                    lineHeight = 19.sp,
                )
                HorizontalDivider(color = PreviewBorder)
                Text(
                    stringResource(R.string.apk_analysis_credit_cost),
                    color = PreviewText,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 15.sp,
                )
                Text(
                    stringResource(R.string.apk_analysis_credit_price),
                    color = PreviewText,
                    fontWeight = FontWeight.SemiBold,
                    fontSize = 15.sp,
                )
                Text(
                    stringResource(R.string.apk_analysis_price_note),
                    color = PreviewMuted,
                    fontSize = 12.sp,
                    lineHeight = 18.sp,
                )
            }
        }

        Row(
            horizontalArrangement = Arrangement.spacedBy(10.dp),
            verticalAlignment = Alignment.Top,
            modifier = Modifier.fillMaxWidth(),
        ) {
            Icon(Icons.Outlined.Info, contentDescription = null,
                tint = PreviewMuted, modifier = Modifier.size(19.dp))
            Text(
                stringResource(R.string.apk_analysis_safety_note),
                color = PreviewMuted,
                fontSize = 12.sp,
                lineHeight = 18.sp,
                modifier = Modifier.weight(1f),
            )
        }

        // A disabled button is intentionally inert: no picker, purchase or charge.
        OutlinedButton(
            onClick = {},
            enabled = false,
            modifier = Modifier.fillMaxWidth().testTag("apk_analysis_import_disabled"),
            shape = RoundedCornerShape(13.dp),
        ) {
            Icon(Icons.Outlined.Description, contentDescription = null)
            Spacer(Modifier.width(8.dp))
            Text(stringResource(R.string.apk_analysis_import_unavailable))
        }
        Text(
            stringResource(R.string.apk_analysis_no_charge),
            color = PreviewMuted,
            fontSize = 12.sp,
            textAlign = TextAlign.Center,
            modifier = Modifier.fillMaxWidth().padding(bottom = 12.dp),
        )
    }
}

@Composable
private fun PreviewStep(number: String, label: Int) {
    Row(
        modifier = Modifier.fillMaxWidth().padding(vertical = 13.dp),
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(13.dp),
    ) {
        Surface(
            shape = RoundedCornerShape(10.dp),
            color = Color(0xFF353535),
        ) {
            Text(number, color = PreviewText, fontSize = 12.sp,
                fontWeight = FontWeight.Bold,
                modifier = Modifier.padding(horizontal = 10.dp, vertical = 8.dp))
        }
        Text(stringResource(label), color = PreviewText,
            fontSize = 14.sp, lineHeight = 20.sp, modifier = Modifier.weight(1f))
    }
}
