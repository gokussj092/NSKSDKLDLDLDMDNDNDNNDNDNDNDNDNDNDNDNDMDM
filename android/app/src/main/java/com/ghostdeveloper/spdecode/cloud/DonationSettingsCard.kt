package com.ghostdeveloper.spdecode.cloud

import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.widget.Toast
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.res.painterResource
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import com.ghostdeveloper.spdecode.R

@Composable
internal fun DonationSettingsCard() {
    val context=LocalContext.current
    Card(shape=RoundedCornerShape(18.dp),colors=CardDefaults.cardColors(
        containerColor=MaterialTheme.colorScheme.surfaceVariant)) {
        Column(Modifier.fillMaxWidth().padding(16.dp),verticalArrangement=Arrangement.spacedBy(10.dp)) {
            Text(stringResource(R.string.donations_title),style=MaterialTheme.typography.titleMedium)
            ListItem(headlineContent={Text("Binance")},
                supportingContent={Text("Ghost Developer\nID: 1233239512")},
                leadingContent={DonationIcon(false)},trailingContent={
                    TextButton(onClick={
                        (context.getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager)
                            .setPrimaryClip(ClipData.newPlainText("Binance ID","1233239512"))
                        Toast.makeText(context,R.string.donation_id_copied,Toast.LENGTH_SHORT).show()
                    }){Text(stringResource(R.string.donation_copy_id))}
                },colors=ListItemDefaults.colors(containerColor=MaterialTheme.colorScheme.surfaceVariant))
            HorizontalDivider(color=MaterialTheme.colorScheme.outlineVariant)
            ListItem(headlineContent={Text("PayPal")},
                supportingContent={Text(stringResource(R.string.donation_coming_soon))},
                leadingContent={DonationIcon(true)},
                colors=ListItemDefaults.colors(containerColor=MaterialTheme.colorScheme.surfaceVariant))
        }
    }
}

/** Local brand SVG paths packaged as Android VectorDrawables; no network or theme tint. */
@Composable
private fun DonationIcon(paypal:Boolean) {
    Image(
        painter=painterResource(if(paypal) R.drawable.ic_donation_paypal else R.drawable.ic_donation_binance),
        contentDescription=null, // ListItem already announces the payment service.
        modifier=Modifier.size(28.dp),
    )
}
