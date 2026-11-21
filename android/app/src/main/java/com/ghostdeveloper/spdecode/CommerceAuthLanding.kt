package com.ghostdeveloper.spdecode

import android.widget.ImageView
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.selection.selectable
import androidx.compose.foundation.selection.selectableGroup
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Fingerprint
import androidx.compose.material.icons.outlined.Lock
import androidx.compose.material.icons.outlined.MailOutline
import androidx.compose.material.icons.outlined.Visibility
import androidx.compose.material.icons.outlined.VisibilityOff
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.focus.FocusRequester
import androidx.compose.ui.focus.focusRequester
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalFocusManager
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.liveRegion
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

private object AuthLandingLanguage {
    private val keys=listOf("Sign in","Create account","Create account with Google")
    private val translated=mapOf(
        "pt" to "Entrar|Criar conta|Criar conta com Google",
        "fr" to "Connexion|Créer un compte|Créer avec Google",
        "de" to "Anmelden|Konto erstellen|Google-Konto erstellen",
        "it" to "Accedi|Crea account|Crea account con Google",
        "tr" to "Giriş yap|Hesap oluştur|Google ile hesap oluştur",
        "ru" to "Войти|Создать аккаунт|Создать аккаунт Google",
        "ar" to "تسجيل الدخول|إنشاء حساب|إنشاء حساب عبر Google",
        "fa" to "ورود|ایجاد حساب|ساخت حساب با گوگل",
        "hi" to "लॉगिन|खाता बनाएँ|Google से खाता बनाएँ",
        "ja" to "ログイン|アカウント作成|Googleでアカウント作成",
        "id" to "Masuk|Buat akun|Buat akun dengan Google",
        "vi" to "Đăng nhập|Tạo tài khoản|Tạo tài khoản với Google",
    ).mapValues{it.value.split("|")}
    fun text(lang:String,es:String,en:String):String{
        val idx=keys.indexOf(en)
        if(idx<0)return CommerceI18n.translate(lang,es,en)
        return when(val normalized=lang.lowercase(java.util.Locale.ROOT)){
            "es"->es
            "en"->en
            else->translated[if(normalized=="in")"id" else normalized]?.getOrNull(idx)?:en
        }
    }
}

private val authPanel = Color(0xFF151515)
private val authStroke = Color(0xFF444444)
private val authPrimary = Color(0xFFF7F7F7)
private val authMuted = Color(0xFFB3B3B3)
private val authShape = RoundedCornerShape(16.dp)

/** Both email steps use the existing account entry point and legal footer. */
@Composable
internal fun CommerceAuthLanding(
    language: String,
    accepted: Boolean,
    busy: Boolean,
    error: String?,
    email: String,
    onEmailChange: (String) -> Unit,
    validEmail: Boolean,
    passwordStep: Boolean,
    password: String,
    onPasswordChange: (String) -> Unit,
    onEmailNext: () -> Unit,
    onEditEmail: () -> Unit,
    onEmailSignIn: () -> Unit,
    onQuickSignIn: (() -> Unit)?,
    onAccepted: (Boolean) -> Unit,
    onLegalLink: (String) -> Unit,
    onGoogle: () -> Unit,
    onClearError: () -> Unit,
) {
    val t: (String, String) -> String = { es, en -> AuthLandingLanguage.text(language,es,en) }
    val signIn = t("Iniciar sesión","Sign in")
    val register = t("Crear cuenta","Create account")
    val passwordFocus = remember { FocusRequester() }
    val focus = LocalFocusManager.current
    var creatingAccount by rememberSaveable { mutableStateOf(false) }
    var showPassword by remember(passwordStep) { mutableStateOf(false) }
    var showRecovery by remember(passwordStep) { mutableStateOf(false) }
    var needsConsent by remember { mutableStateOf(false) }
    val canSubmitPassword = password.isNotEmpty() && !busy

    LaunchedEffect(passwordStep) {
        if (passwordStep) passwordFocus.requestFocus()
    }
    LaunchedEffect(busy) {
        if (busy) showPassword = false
    }

    Column(
        Modifier.fillMaxWidth().padding(bottom = 12.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
    ) {
        Column(
            Modifier.widthIn(max = 420.dp).fillMaxWidth(),
            horizontalAlignment = Alignment.CenterHorizontally,
            verticalArrangement = Arrangement.spacedBy(13.dp),
        ) {
            AuthAppIcon()
            Text("SP-DECODE", color = authMuted, letterSpacing = 2.sp,
                fontSize = 12.sp, fontWeight = FontWeight.SemiBold, textAlign = TextAlign.Center)
            Text(
                if (creatingAccount) register else signIn,
                color = authPrimary, fontSize = 28.sp, fontWeight = FontWeight.Bold,
                textAlign = TextAlign.Center,
            )

            if (!passwordStep) {
                Row(
                    Modifier.fillMaxWidth().selectableGroup().background(authPanel, authShape).padding(4.dp),
                    horizontalArrangement = Arrangement.spacedBy(4.dp),
                ) {
                    listOf(signIn, register).forEachIndexed { index, label ->
                        val selected = creatingAccount == (index == 1)
                        Box(
                            Modifier.weight(1f).clip(RoundedCornerShape(12.dp))
                                .background(if (selected) authPrimary else Color.Transparent)
                                .selectable(
                                    selected = selected, enabled = !busy, role = Role.Tab,
                                    onClick = {
                                        focus.clearFocus()
                                        creatingAccount = index == 1
                                        needsConsent = false
                                        onClearError()
                                    },
                                )
                                .heightIn(min = 46.dp).padding(horizontal = 7.dp, vertical = 8.dp),
                            contentAlignment = Alignment.Center,
                        ) {
                            Text(label, color = if (selected) Color.Black else authMuted,
                                fontSize = 13.sp, fontWeight = FontWeight.SemiBold,
                                textAlign = TextAlign.Center)
                        }
                    }
                }
            }

            if (!creatingAccount) {
                if (passwordStep) {
                    Row(
                        Modifier.fillMaxWidth().background(authPanel, authShape)
                            .padding(start = 14.dp, end = 6.dp),
                        verticalAlignment = Alignment.CenterVertically,
                    ) {
                        Text(email, modifier = Modifier.weight(1f), color = authPrimary,
                            fontSize = 14.sp, maxLines = 2, overflow = TextOverflow.Ellipsis)
                        TextButton(onClick = onEditEmail, enabled = !busy) {
                            Text(stringResource(R.string.account_auth_edit_email), color = authPrimary)
                        }
                    }
                    OutlinedTextField(
                        value = password,
                        onValueChange = onPasswordChange,
                        modifier = Modifier.fillMaxWidth().focusRequester(passwordFocus),
                        enabled = !busy,
                        singleLine = true,
                        shape = authShape,
                        label = { Text(t("Contraseña","Password")) },
                        leadingIcon = { Icon(Icons.Outlined.Lock, contentDescription = null) },
                        trailingIcon = {
                            IconButton(onClick = { showPassword = !showPassword }, enabled = !busy) {
                                Icon(
                                    if (showPassword) Icons.Outlined.VisibilityOff else Icons.Outlined.Visibility,
                                    contentDescription = stringResource(
                                        if (showPassword) R.string.account_auth_hide_password
                                        else R.string.account_auth_show_password,
                                    ),
                                )
                            }
                        },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Password, imeAction = ImeAction.Done),
                        keyboardActions = KeyboardActions(onDone = {
                            if (canSubmitPassword) {
                                focus.clearFocus()
                                onEmailSignIn()
                            }
                        }),
                        visualTransformation =
                            if (showPassword) VisualTransformation.None else PasswordVisualTransformation(),
                        colors = authFieldColors(),
                    )
                    TextButton(
                        onClick = { showRecovery = !showRecovery },
                        modifier = Modifier.align(Alignment.End),
                        enabled = !busy,
                    ) {
                        Text(stringResource(R.string.account_auth_forgot_password), color = authPrimary)
                    }
                    if (showRecovery) {
                        Text(stringResource(R.string.account_auth_recovery_hint),
                            modifier = Modifier.fillMaxWidth(), color = authMuted,
                            fontSize = 13.sp, lineHeight = 18.sp)
                    }
                    AuthPrimaryButton(signIn, enabled = canSubmitPassword) {
                        focus.clearFocus()
                        onEmailSignIn()
                    }
                } else {
                    OutlinedTextField(
                        value = email,
                        onValueChange = onEmailChange,
                        modifier = Modifier.fillMaxWidth(),
                        enabled = !busy,
                        singleLine = true,
                        shape = authShape,
                        label = { Text(t("Correo electrónico","Email address")) },
                        leadingIcon = { Icon(Icons.Outlined.MailOutline, contentDescription = null) },
                        keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email, imeAction = ImeAction.Next),
                        keyboardActions = KeyboardActions(onNext = {
                            if (validEmail && !busy) onEmailNext()
                        }),
                        colors = authFieldColors(),
                    )
                    AuthPrimaryButton(
                        stringResource(R.string.account_auth_next),
                        enabled = validEmail && !busy,
                        onClick = onEmailNext,
                    )
                }
                Row(
                    Modifier.fillMaxWidth().padding(vertical = 3.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.spacedBy(11.dp),
                ) {
                    HorizontalDivider(Modifier.weight(1f), color = authStroke)
                    Text(stringResource(R.string.account_auth_or_continue_with),
                        color = authMuted, fontSize = 12.sp, textAlign = TextAlign.Center)
                    HorizontalDivider(Modifier.weight(1f), color = authStroke)
                }
            }

            OutlinedButton(
                onClick = {
                    focus.clearFocus()
                    onClearError()
                    if (accepted) onGoogle() else needsConsent = true
                },
                enabled = !busy,
                modifier = Modifier.fillMaxWidth().heightIn(min = 52.dp),
                shape = authShape,
                border = BorderStroke(1.dp, authStroke),
                colors = ButtonDefaults.outlinedButtonColors(
                    containerColor = authPanel, contentColor = authPrimary,
                    disabledContentColor = authMuted,
                ),
            ) {
                Box(Modifier.size(26.dp).background(Color.White, RoundedCornerShape(50)),
                    contentAlignment = Alignment.Center) {
                    Text("G", color = Color(0xFF4285F4), fontSize = 18.sp, fontWeight = FontWeight.Bold)
                }
                Spacer(Modifier.width(10.dp))
                Text(
                    if (creatingAccount) t("Crear cuenta con Google","Create account with Google")
                    else "Google",
                    fontWeight = FontWeight.Medium, textAlign = TextAlign.Center,
                )
            }

            if (!creatingAccount && onQuickSignIn != null) {
                TextButton(
                    onClick = {
                        focus.clearFocus()
                        onQuickSignIn()
                    },
                    enabled = !busy,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.textButtonColors(contentColor = authPrimary),
                ) {
                    Icon(Icons.Outlined.Fingerprint, contentDescription = null,
                        modifier = Modifier.size(19.dp))
                    Spacer(Modifier.width(8.dp))
                    Text(stringResource(R.string.account_auth_quick_access), textAlign = TextAlign.Center)
                }
            }
            if (busy) LinearProgressIndicator(Modifier.fillMaxWidth(), color = authPrimary, trackColor = authStroke)
            if (error != null) {
                Text(error, Modifier.fillMaxWidth().semantics { liveRegion = LiveRegionMode.Polite },
                    color = authPrimary, fontSize = 13.sp, lineHeight = 18.sp)
            }
            if (needsConsent && !accepted) {
                Text(stringResource(R.string.account_auth_consent_required),
                    Modifier.fillMaxWidth().semantics { liveRegion = LiveRegionMode.Polite },
                    color = authPrimary, fontSize = 13.sp, lineHeight = 18.sp)
            }
            HorizontalDivider(color = authStroke)
            CommerceConsentRow(language,accepted,onAccepted,onLegalLink)
        }
    }
}

@Composable
private fun AuthAppIcon() {
    Box(
        Modifier.size(68.dp).background(authPanel, RoundedCornerShape(20.dp))
            .border(1.dp, authStroke, RoundedCornerShape(20.dp)),
        contentAlignment = Alignment.Center,
    ) {
        // ImageView supports the adaptive launcher icon resource used on API 26+.
        AndroidView(
            factory = { ctx ->
                ImageView(ctx).apply {
                    scaleType = ImageView.ScaleType.FIT_CENTER
                    val installedIcon = runCatching {
                        ctx.packageManager.getApplicationIcon(ctx.packageName)
                    }.getOrNull()
                    if (installedIcon != null) setImageDrawable(installedIcon)
                    else setImageResource(R.drawable.ic_launcher_foreground)
                }
            },
            modifier = Modifier.size(56.dp),
        )
    }
}

@Composable
private fun AuthPrimaryButton(label: String, enabled: Boolean, onClick: () -> Unit) {
    Button(
        onClick = onClick, enabled = enabled, modifier = Modifier.fillMaxWidth().heightIn(min = 50.dp),
        shape = authShape, colors = ButtonDefaults.buttonColors(
            containerColor = authPrimary, contentColor = Color.Black,
            disabledContainerColor = authPanel, disabledContentColor = authMuted,
        ),
    ) {
        Text(label, fontWeight = FontWeight.SemiBold, textAlign = TextAlign.Center)
    }
}

@Composable
private fun authFieldColors() = OutlinedTextFieldDefaults.colors(
    focusedTextColor = authPrimary, unfocusedTextColor = authPrimary, disabledTextColor = authMuted,
    focusedContainerColor = authPanel, unfocusedContainerColor = authPanel, disabledContainerColor = authPanel,
    focusedBorderColor = authPrimary, unfocusedBorderColor = authStroke, disabledBorderColor = authStroke,
    focusedLabelColor = authPrimary, unfocusedLabelColor = authMuted, disabledLabelColor = authMuted,
    focusedLeadingIconColor = authPrimary, unfocusedLeadingIconColor = authMuted,
    focusedTrailingIconColor = authPrimary, unfocusedTrailingIconColor = authMuted,
    cursorColor = authPrimary,
)
