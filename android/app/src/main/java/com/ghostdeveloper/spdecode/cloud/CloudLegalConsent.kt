package com.ghostdeveloper.spdecode.cloud

import android.content.Context
import com.ghostdeveloper.spdecode.R
import androidx.compose.ui.res.stringResource
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.padding
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.Checkbox
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import org.json.JSONObject

internal object CloudLegalConsent {
    const val VERSION=20261018
    const val TERMS="https://spdecode.xyz/terms"
    const val PRIVACY="https://spdecode.xyz/privacy"

    fun accepted(context:Context):Boolean = try {
        val bytes=ServerVpnSecureCache(context).read("legal")
        val record=bytes?.toString(Charsets.UTF_8)?.let(::JSONObject)
        record?.optInt("version")==VERSION && record.optBoolean("accepted",false)
    }catch (_:Exception){false}

    fun accept(context:Context) {
        val record=JSONObject().put("version",VERSION).put("accepted",true)
            .put("atMillis",System.currentTimeMillis())
        ServerVpnSecureCache(context).write("legal",record.toString().toByteArray(Charsets.UTF_8))
    }
    /** Withdrawal blocks all future Cloud requests while leaving user-owned
     * encrypted history untouched. A later acceptance requires a new tap. */
    fun revoke(context:Context) {
        ServerVpnSecureCache(context).delete("legal")
    }
}

@Composable
internal fun CloudLegalConsentDialog(
    onTerms:()->Unit,
    onPrivacy:()->Unit,
    onAccept:()->Unit,
    onDecline:()->Unit,
) {
    var checked by remember { mutableStateOf(false) }
    AlertDialog(
        onDismissRequest = {},
        title = { Text(stringResource(R.string.cloud_legal_title)) },
        text = {
            Column {
                Text(stringResource(R.string.cloud_legal_explanation))
                TextButton(onClick=onTerms){Text(stringResource(R.string.cloud_legal_terms))}
                TextButton(onClick=onPrivacy){Text(stringResource(R.string.cloud_legal_privacy))}
                androidx.compose.foundation.layout.Row(modifier=Modifier.fillMaxWidth()) {
                    Checkbox(checked=checked,onCheckedChange={checked=it})
                    Text(stringResource(R.string.cloud_legal_accept_check),
                        modifier=Modifier.padding(top=10.dp))
                }
            }
        },
        confirmButton={ Button(onClick=onAccept,enabled=checked){Text(stringResource(R.string.cloud_legal_accept))} },
        dismissButton={ TextButton(onClick=onDecline){Text(stringResource(R.string.cloud_legal_decline))} },
    )
}
