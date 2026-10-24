package com.ghostdeveloper.spdecode

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.input.KeyboardCapitalization
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.window.DialogProperties
import androidx.compose.ui.window.SecureFlagPolicy
import androidx.compose.ui.unit.dp

/** Password requested only after the authenticated Cloud worker signals
 * PASSWORD_REQUIRED. No password is persisted or included in analytics. */
@Composable
internal fun CloudPasswordDialog(
    label: String,
    onSubmit: (String)->Unit,
    onCancel: ()->Unit,
) {
    var password by remember(label) { mutableStateOf("") }
    fun cancel() { password="";onCancel() }
    AlertDialog(
        onDismissRequest={cancel()},
        properties=DialogProperties(securePolicy=SecureFlagPolicy.SecureOn),
        icon={Icon(Icons.Outlined.Lock,null)},
        title={Text(stringResource(R.string.cloud_password_title))},
        text={
            Column(verticalArrangement=Arrangement.spacedBy(12.dp)) {
                Text(stringResource(R.string.cloud_password_description,label))
                OutlinedTextField(
                    value=password,
                    onValueChange={if(it.toByteArray(Charsets.UTF_8).size<=4096)password=it},
                    label={Text(stringResource(R.string.hc_auth_password))},
                    visualTransformation=PasswordVisualTransformation(),
                    singleLine=true,
                    modifier=Modifier.fillMaxWidth(),
                    keyboardOptions=KeyboardOptions(
                        capitalization=KeyboardCapitalization.None,
                        autoCorrectEnabled=false,
                    ),
                )
            }
        },
        confirmButton={TextButton(
            enabled=password.isNotEmpty(),
            onClick={val value=password; password="";onSubmit(value)}
        ){Text(stringResource(R.string.hc_auth_unlock))}},
        dismissButton={TextButton(onClick={cancel()}) {
            Text(stringResource(R.string.cancel))
        }},
        shape=RoundedCornerShape(17.dp),
        containerColor=Color.Black,
        titleContentColor=Color(0xFFF7F7F7),
        textContentColor=Color(0xFFF7F7F7),
        iconContentColor=Color(0xFFF7F7F7),
        tonalElevation=0.dp,
    )
}
