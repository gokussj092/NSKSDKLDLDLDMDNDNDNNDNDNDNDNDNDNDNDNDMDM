package com.ghostdeveloper.spdecode

import androidx.compose.foundation.background
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.PasswordVisualTransformation
import androidx.compose.ui.text.input.VisualTransformation
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.launch
import org.json.JSONObject
import java.util.Locale

internal object CommerceSecurityText {
    private val en=listOf("Password","Add password","Change password","Current password",
        "New password","Confirm new password","Save password","Passwords do not match",
        "At least 12 characters","Password updated","Unable to update password",
        "Verify your Google account","Fingerprint or phone PIN","Protect account",
        "Unlock account","Confirm with your device","Device lock unavailable",
        "Already linked to Google","Email sign-in","Account security",
        "Wrong current password","Confirm password to continue",
        "Device protection","Google verification required","Password required")
    private val es=listOf("Contraseña","Añadir contraseña","Cambiar contraseña","Contraseña actual",
        "Nueva contraseña","Confirmar nueva contraseña","Guardar contraseña",
        "Las contraseñas no coinciden","Mínimo 12 caracteres","Contraseña actualizada",
        "No se pudo actualizar la contraseña","Verifica tu cuenta de Google",
        "Huella o PIN del teléfono","Proteger cuenta","Desbloquear cuenta",
        "Confirma con tu dispositivo","Bloqueo del dispositivo no disponible",
        "Vinculada a Google","Acceso con correo","Seguridad de la cuenta",
        "Contraseña actual incorrecta","Confirma tu contraseña para continuar",
        "Protección del dispositivo","Se requiere verificación de Google",
        "Contraseña obligatoria")
    private val other=mapOf(
        "pt" to "Senha|Adicionar senha|Alterar senha|Senha atual|Nova senha|Confirmar nova senha|Salvar senha|Senhas não coincidem|Pelo menos 12 caracteres|Senha atualizada|Não foi possível alterar a senha|Verifique sua conta Google|Digital ou PIN do telefone|Proteger conta|Desbloquear conta|Confirme no dispositivo|Bloqueio indisponível|Vinculada ao Google|Entrar com e-mail|Segurança da conta|Senha atual incorreta|Confirme a senha para continuar|Proteção do dispositivo|Verificação Google necessária|Senha obrigatória",
        "fr" to "Mot de passe|Ajouter un mot de passe|Modifier le mot de passe|Mot de passe actuel|Nouveau mot de passe|Confirmer le mot de passe|Enregistrer|Les mots de passe diffèrent|Au moins 12 caractères|Mot de passe modifié|Modification impossible|Vérifiez votre compte Google|Empreinte ou code du téléphone|Protéger le compte|Déverrouiller le compte|Confirmer sur l’appareil|Verrouillage indisponible|Lié à Google|Connexion par e-mail|Sécurité du compte|Mot de passe actuel incorrect|Confirmez le mot de passe|Protection de l’appareil|Vérification Google requise|Mot de passe requis",
        "de" to "Passwort|Passwort hinzufügen|Passwort ändern|Aktuelles Passwort|Neues Passwort|Neues Passwort bestätigen|Passwort speichern|Passwörter stimmen nicht überein|Mindestens 12 Zeichen|Passwort aktualisiert|Passwortänderung fehlgeschlagen|Google-Konto bestätigen|Fingerabdruck oder Geräte-PIN|Konto schützen|Konto entsperren|Auf Gerät bestätigen|Gerätesperre nicht verfügbar|Mit Google verknüpft|E-Mail-Anmeldung|Kontosicherheit|Aktuelles Passwort falsch|Passwort bestätigen|Geräteschutz|Google-Bestätigung erforderlich|Passwort erforderlich",
        "it" to "Password|Aggiungi password|Cambia password|Password attuale|Nuova password|Conferma nuova password|Salva password|Le password non coincidono|Almeno 12 caratteri|Password aggiornata|Impossibile aggiornare la password|Verifica account Google|Impronta o PIN del telefono|Proteggi account|Sblocca account|Conferma sul dispositivo|Blocco dispositivo non disponibile|Collegato a Google|Accesso con e-mail|Sicurezza account|Password attuale errata|Conferma la password|Protezione dispositivo|Verifica Google richiesta|Password obbligatoria",
        "ru" to "Пароль|Добавить пароль|Сменить пароль|Текущий пароль|Новый пароль|Подтвердить новый пароль|Сохранить пароль|Пароли не совпадают|Не менее 12 символов|Пароль обновлён|Не удалось изменить пароль|Подтвердите Google-аккаунт|Отпечаток или PIN телефона|Защитить аккаунт|Разблокировать аккаунт|Подтвердите на устройстве|Защита устройства недоступна|Связан с Google|Вход по почте|Безопасность аккаунта|Неверный текущий пароль|Подтвердите пароль|Защита устройства|Нужна проверка Google|Требуется пароль",
        "tr" to "Şifre|Şifre ekle|Şifre değiştir|Mevcut şifre|Yeni şifre|Yeni şifreyi onayla|Şifreyi kaydet|Şifreler eşleşmiyor|En az 12 karakter|Şifre güncellendi|Şifre güncellenemedi|Google hesabını doğrula|Parmak izi veya telefon PIN'i|Hesabı koru|Hesap kilidini aç|Cihazda onayla|Cihaz kilidi yok|Google'a bağlı|E-posta ile giriş|Hesap güvenliği|Mevcut şifre yanlış|Şifreyi doğrula|Cihaz koruması|Google doğrulaması gerekli|Şifre gerekli",
        "ar" to "كلمة المرور|إضافة كلمة مرور|تغيير كلمة المرور|كلمة المرور الحالية|كلمة مرور جديدة|تأكيد كلمة المرور|حفظ كلمة المرور|كلمتا المرور غير متطابقتين|12 حرفًا على الأقل|تم تحديث كلمة المرور|تعذر التحديث|تحقق من حساب Google|البصمة أو رمز الهاتف|حماية الحساب|فتح قفل الحساب|تأكيد على الجهاز|قفل الجهاز غير متاح|مرتبط بـ Google|الدخول بالبريد|أمان الحساب|كلمة المرور الحالية خاطئة|أكد كلمة المرور|حماية الجهاز|مطلوب تحقق Google|كلمة المرور مطلوبة",
        "fa" to "رمز عبور|افزودن رمز عبور|تغییر رمز عبور|رمز عبور فعلی|رمز عبور جدید|تأیید رمز جدید|ذخیره رمز|رمزها مطابقت ندارند|حداقل ۱۲ نویسه|رمز عبور تغییر کرد|تغییر رمز ممکن نشد|حساب گوگل را تأیید کنید|اثر انگشت یا پین|محافظت از حساب|باز کردن قفل|با دستگاه تأیید کنید|قفل دستگاه موجود نیست|متصل به گوگل|ورود با ایمیل|امنیت حساب|رمز قبلی اشتباه است|رمز را تأیید کنید|حفاظت دستگاه|تأیید گوگل لازم است|رمز لازم است",
        "hi" to "पासवर्ड|पासवर्ड जोड़ें|पासवर्ड बदलें|मौजूदा पासवर्ड|नया पासवर्ड|नया पासवर्ड पुष्टि|पासवर्ड सहेजें|पासवर्ड मेल नहीं खाते|कम से कम 12 अक्षर|पासवर्ड अपडेट हुआ|पासवर्ड अपडेट नहीं हुआ|Google खाता सत्यापित करें|फिंगरप्रिंट या फोन PIN|खाता सुरक्षित करें|खाता अनलॉक करें|डिवाइस पर पुष्टि करें|डिवाइस लॉक उपलब्ध नहीं|Google से जुड़ा|ईमेल लॉगिन|खाता सुरक्षा|मौजूदा पासवर्ड गलत|पासवर्ड की पुष्टि करें|डिवाइस सुरक्षा|Google पुष्टि आवश्यक|पासवर्ड आवश्यक",
        "ja" to "パスワード|パスワードを追加|パスワードを変更|現在のパスワード|新しいパスワード|新しいパスワードを確認|パスワードを保存|パスワードが一致しません|12文字以上|パスワードを更新しました|更新できませんでした|Googleアカウントを確認|指紋または端末PIN|アカウントを保護|アカウントのロック解除|端末で確認|端末ロック非対応|Google連携済み|メールでログイン|アカウントのセキュリティ|現在のパスワードが違います|パスワードを確認|端末の保護|Googleの確認が必要|パスワードが必要",
        "id" to "Kata sandi|Tambahkan kata sandi|Ubah kata sandi|Kata sandi saat ini|Kata sandi baru|Konfirmasi kata sandi|Simpan kata sandi|Kata sandi tidak sama|Minimal 12 karakter|Kata sandi diperbarui|Gagal memperbarui kata sandi|Verifikasi akun Google|Sidik jari atau PIN ponsel|Lindungi akun|Buka kunci akun|Konfirmasi di perangkat|Kunci perangkat tidak tersedia|Terhubung Google|Masuk dengan email|Keamanan akun|Kata sandi lama salah|Konfirmasi kata sandi|Perlindungan perangkat|Verifikasi Google diperlukan|Kata sandi wajib",
        "vi" to "Mật khẩu|Thêm mật khẩu|Đổi mật khẩu|Mật khẩu hiện tại|Mật khẩu mới|Xác nhận mật khẩu|Lưu mật khẩu|Mật khẩu không khớp|Ít nhất 12 ký tự|Đã cập nhật mật khẩu|Không thể cập nhật mật khẩu|Xác minh tài khoản Google|Vân tay hoặc PIN điện thoại|Bảo vệ tài khoản|Mở khóa tài khoản|Xác nhận trên thiết bị|Không có khóa thiết bị|Đã liên kết Google|Đăng nhập bằng email|Bảo mật tài khoản|Sai mật khẩu hiện tại|Xác nhận mật khẩu|Bảo vệ thiết bị|Cần xác minh Google|Cần mật khẩu"
    ).mapValues{it.value.split("|")}
    fun get(language:String,key:String):String {
        val i=en.indexOf(key)
        if(i<0)return key
        return when(language.lowercase(Locale.ROOT)){
            "es"->es[i]
            "in"->other["id"]?.getOrNull(i)?:key
            else->other[language.lowercase(Locale.ROOT)]?.getOrNull(i)?:key
        }
    }
}

@Composable
internal fun CommercePasswordPage(language:String,auth:NativeCommerceAuth,
    user:CommerceIdentity?,hasPassword:Boolean,onSaved:(JSONObject)->Unit){
    val tr:(String)->String={CommerceSecurityText.get(language,it)}
    val scope=rememberCoroutineScope()
    var old by remember {mutableStateOf("")}
    var newer by remember {mutableStateOf("")}
    var confirm by remember {mutableStateOf("")}
    var submitting by remember {mutableStateOf(false)}
    var error by remember {mutableStateOf<String?>(null)}
    var reveal by remember {mutableStateOf(false)}
    val valid=newer.length in 12..128 && newer==confirm &&
        (!hasPassword||old.isNotEmpty())
    Column(verticalArrangement=Arrangement.spacedBy(17.dp)){
        Text(if(hasPassword)tr("Change password") else tr("Add password"),
            color=Color.White,fontSize=27.sp,fontWeight=FontWeight.Bold)
        Column(Modifier.fillMaxWidth().background(Color(0xFF222222),RoundedCornerShape(22.dp))
            .padding(19.dp),verticalArrangement=Arrangement.spacedBy(15.dp)){
            Icon(Icons.Outlined.Lock,null,tint=Color(0xFFB8DCC0),
                modifier=Modifier.size(34.dp))
            if(hasPassword)OutlinedTextField(old,{old=it.take(128)},
                modifier=Modifier.fillMaxWidth(),singleLine=true,
                visualTransformation=if(reveal)VisualTransformation.None else PasswordVisualTransformation(),
                label={Text(tr("Current password"))})
            OutlinedTextField(newer,{newer=it.take(128)},modifier=Modifier.fillMaxWidth(),
                singleLine=true,visualTransformation=if(reveal)VisualTransformation.None else PasswordVisualTransformation(),
                label={Text(tr("New password"))})
            OutlinedTextField(confirm,{confirm=it.take(128)},modifier=Modifier.fillMaxWidth(),
                singleLine=true,visualTransformation=if(reveal)VisualTransformation.None else PasswordVisualTransformation(),
                label={Text(tr("Confirm new password"))})
            Row(verticalAlignment=Alignment.CenterVertically){
                Checkbox(checked=reveal,onCheckedChange={reveal=it})
                Text(CommerceI18n.translate(language,"Mostrar contraseñas","Show passwords"),
                    color=Color(0xFFDDDDDD),fontSize=13.sp)
            }
            Text(tr("At least 12 characters"),color=Color(0xFFBBBBBB),fontSize=12.sp)
            if(newer.isNotBlank()&&confirm.isNotBlank()&&newer!=confirm)
                Text(tr("Passwords do not match"),color=Color(0xFFF2B4B4),fontSize=12.sp)
            if(!hasPassword)Text(tr("Google verification required"),
                color=Color(0xFFB8DCC0),fontSize=12.sp)
            if(error!=null)Text(error.orEmpty(),color=Color(0xFFF2B4B4),fontSize=13.sp)
            Button(enabled=valid&&!submitting&&user!=null,
                modifier=Modifier.fillMaxWidth(),onClick={
                    scope.launch{
                        submitting=true;error=null
                        try{
                            val current=user?:throw IllegalStateException("SIGN_IN_REQUIRED")
                            try{
                                auth.changeAccountPassword(if(hasPassword)old else null,newer)
                            }catch(e:NativeCommerceAuth.AuthFailure){
                                if(!hasPassword&&e.code=="REAUTHENTICATION_REQUIRED"){
                                    auth.reauthenticateWithGoogle(current.id)
                                    auth.changeAccountPassword(null,newer)
                                }else throw e
                            }
                            old="";newer="";confirm=""
                            onSaved(auth.account()?:throw IllegalStateException("SIGN_IN_REQUIRED"))
                        }catch(e:CancellationException){throw e}
                        catch(e:Exception){
                            error=when(NativeCommerceAuth.diagnostic(e)){
                                "CURRENT_PASSWORD_INVALID"->tr("Wrong current password")
                                "REAUTHENTICATION_REQUIRED"->tr("Google verification required")
                                else->tr("Unable to update password")
                            }
                        }finally{submitting=false}
                    }
                },colors=ButtonDefaults.buttonColors(containerColor=Color.White,contentColor=Color.Black)){
                Icon(Icons.Outlined.Check,null)
                Spacer(Modifier.width(8.dp))
                Text(tr("Save password"))
            }
            if(submitting)LinearProgressIndicator(Modifier.fillMaxWidth())
        }
    }
}

@Composable
internal fun CommerceDeviceAccountSettings(language:String){
    val context=LocalContext.current
    val tr:(String)->String={CommerceSecurityText.get(language,it)}
    var selected by remember {mutableStateOf(NativeDeviceAccountGuard.enabled(context))}
    var working by remember {mutableStateOf(false)}
    val supported=NativeDeviceAccountGuard.supported(context)
    Row(Modifier.fillMaxWidth().background(Color(0xFF222222),RoundedCornerShape(20.dp))
        .padding(16.dp),verticalAlignment=Alignment.CenterVertically){
        Icon(Icons.Outlined.Fingerprint,null,tint=Color(0xFFB8DCC0))
        Spacer(Modifier.width(12.dp))
        Column(Modifier.weight(1f)){
            Text(tr("Device protection"),color=Color.White,fontWeight=FontWeight.SemiBold)
            Text(if(supported)tr("Fingerprint or phone PIN") else tr("Device lock unavailable"),
                color=Color(0xFFBBBBBB),fontSize=12.sp)
        }
        Switch(checked=selected,enabled=supported&&!working,onCheckedChange={enabled->
            working=true
            NativeDeviceAccountGuard.authenticate(context,tr("Confirm with your device")){success->
                if(success){
                    NativeDeviceAccountGuard.setEnabled(context,enabled)
                    selected=enabled
                }
                working=false
            }
        })
    }
}

@Composable
internal fun CommerceAccountUnlockPage(language:String){
    val context=LocalContext.current
    val tr:(String)->String={CommerceSecurityText.get(language,it)}
    var busy by remember{mutableStateOf(false)}
    Column(Modifier.fillMaxWidth().padding(16.dp),
        horizontalAlignment=Alignment.CenterHorizontally,
        verticalArrangement=Arrangement.spacedBy(18.dp)){
        Icon(Icons.Outlined.Fingerprint,null,tint=Color(0xFFB8DCC0),
            modifier=Modifier.size(72.dp))
        Text(tr("Unlock account"),color=Color.White,fontSize=26.sp,
            fontWeight=FontWeight.Bold)
        Button(enabled=!busy,onClick={
            busy=true
            NativeDeviceAccountGuard.authenticate(context,tr("Unlock account")){
                busy=false
            }
        },colors=ButtonDefaults.buttonColors(containerColor=Color.White,contentColor=Color.Black)){
            Text(tr("Confirm with your device"))
        }
    }
}
