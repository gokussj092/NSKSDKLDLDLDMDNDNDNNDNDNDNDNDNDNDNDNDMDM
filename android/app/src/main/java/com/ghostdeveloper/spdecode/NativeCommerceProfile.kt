package com.ghostdeveloper.spdecode

import android.content.Context
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.net.Uri
import android.util.Base64
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.*
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.layout.ContentScale
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.json.JSONObject
import java.io.ByteArrayOutputStream
import java.net.HttpURLConnection
import java.net.URL
import java.util.Locale
import kotlin.math.max

/** Public profile fields only; never keeps OAuth ID tokens or bearer tokens in Compose. */
internal data class CommerceIdentity(val id:String,val name:String,val username:String,
    val email:String,val avatar:String?)
internal object CommerceSession {
    var user by mutableStateOf<CommerceIdentity?>(null)
        private set
    var adsExpiry by mutableLongStateOf(0L)
        private set
    var entitlementChecked by mutableStateOf(false)
        private set
    var checkoutPending by mutableStateOf(false)
        private set
    fun beginCheckout(){checkoutPending=true}
    val adFreeActive:Boolean get() {
        val current=user?:return false
        return entitlementChecked && NativeAdsGate.validServerEntitlement(
            current.id,adsExpiry,System.currentTimeMillis())
    }
    val shouldHideAds:Boolean get()=checkoutPending||adFreeActive
    fun update(snapshot:JSONObject) {
        val data=snapshot.optJSONObject("user")?:return
        val raw=data.optString("avatar").takeUnless{it.isBlank()||it=="null"}
        user=CommerceIdentity(data.optString("id"),data.optString("name"),
            data.optString("username"),data.optString("email"),raw)
        val ad=snapshot.optJSONObject("adsFree")
        adsExpiry=if(ad?.optBoolean("active")==true)
            runCatching{java.time.Instant.parse(ad.optString("expiresAt")).toEpochMilli()}
                .getOrDefault(0L) else 0L
        entitlementChecked=true
        checkoutPending=false
    }
    fun clear(){user=null;adsExpiry=0;entitlementChecked=false;checkoutPending=false}
}
internal object NativeAdsGate {
    init { System.loadLibrary("spdecode_profile") }
    external fun validServerEntitlement(accountId:String,expiryMillis:Long,nowMillis:Long):Boolean
}

internal object CommerceProfileText {
    private val labels=listOf("Edit profile","Your profile","Display name","Unique username",
        "Change photo","Remove photo","Save changes","Cancel","Profile updated",
        "Username taken","Sign in again to edit","Invalid name or username",
        "Photo could not be processed","Profile photo","Google account",
        "Your changes are protected by your account session",
        "Username changes are allowed once every seven days")
    private val es=listOf("Editar perfil","Tu perfil","Nombre para mostrar","Usuario único",
        "Cambiar foto","Quitar foto","Guardar cambios","Cancelar","Perfil actualizado",
        "Ese usuario ya existe","Inicia sesión otra vez para editar","Nombre o usuario inválido",
        "No se pudo procesar la foto","Foto de perfil","Cuenta Google",
        "Tus cambios están protegidos por la sesión de tu cuenta",
        "Solo puedes cambiar tu usuario cada siete días")
    private val languages=mapOf(
        "pt" to "Editar perfil|Seu perfil|Nome de exibição|Nome de usuário único|Alterar foto|Remover foto|Salvar alterações|Cancelar|Perfil atualizado|Usuário já existe|Entre novamente para editar|Nome ou usuário inválido|Não foi possível processar a foto|Foto de perfil|Conta Google|Suas alterações são protegidas pela sessão|O usuário só pode mudar a cada sete dias",
        "fr" to "Modifier le profil|Votre profil|Nom affiché|Identifiant unique|Changer la photo|Supprimer la photo|Enregistrer|Annuler|Profil mis à jour|Identifiant déjà pris|Reconnectez-vous pour modifier|Nom ou identifiant invalide|Impossible de traiter la photo|Photo de profil|Compte Google|Les modifications sont protégées par votre session|Changement d'identifiant limité à sept jours",
        "de" to "Profil bearbeiten|Dein Profil|Anzeigename|Eindeutiger Nutzername|Foto ändern|Foto entfernen|Änderungen speichern|Abbrechen|Profil aktualisiert|Nutzername vergeben|Zum Bearbeiten erneut anmelden|Name oder Nutzername ungültig|Foto konnte nicht verarbeitet werden|Profilfoto|Google-Konto|Änderungen sind durch deine Sitzung geschützt|Nutzername nur alle sieben Tage änderbar",
        "it" to "Modifica profilo|Il tuo profilo|Nome visualizzato|Nome utente univoco|Cambia foto|Rimuovi foto|Salva modifiche|Annulla|Profilo aggiornato|Nome utente già usato|Accedi di nuovo per modificare|Nome o utente non valido|Impossibile elaborare la foto|Foto profilo|Account Google|Modifiche protette dalla sessione|Puoi cambiare nome utente ogni sette giorni",
        "tr" to "Profili düzenle|Profilin|Görünen ad|Benzersiz kullanıcı adı|Fotoğrafı değiştir|Fotoğrafı kaldır|Değişiklikleri kaydet|İptal|Profil güncellendi|Kullanıcı adı alınmış|Düzenlemek için tekrar giriş yap|Geçersiz ad veya kullanıcı adı|Fotoğraf işlenemedi|Profil fotoğrafı|Google hesabı|Değişiklikler oturumunla korunur|Kullanıcı adı yedi günde bir değiştirilebilir",
        "ru" to "Изменить профиль|Ваш профиль|Отображаемое имя|Уникальное имя пользователя|Изменить фото|Удалить фото|Сохранить изменения|Отмена|Профиль обновлён|Имя пользователя занято|Войдите снова для изменения|Неверное имя или логин|Не удалось обработать фото|Фото профиля|Аккаунт Google|Изменения защищены вашей сессией|Менять логин можно раз в семь дней",
        "ar" to "تعديل الملف الشخصي|ملفك الشخصي|الاسم الظاهر|اسم مستخدم فريد|تغيير الصورة|إزالة الصورة|حفظ التغييرات|إلغاء|تم تحديث الملف|اسم المستخدم مستخدم|أعد تسجيل الدخول للتعديل|اسم أو مستخدم غير صالح|تعذرت معالجة الصورة|صورة الملف|حساب Google|تغييراتك محمية بجلستك|يمكن تغيير المستخدم كل سبعة أيام",
        "fa" to "ویرایش نمایه|نمایه شما|نام نمایشی|نام کاربری یکتا|تغییر عکس|حذف عکس|ذخیره تغییرات|لغو|نمایه به‌روز شد|نام کاربری گرفته شده|برای ویرایش دوباره وارد شوید|نام یا کاربری نامعتبر|پردازش عکس ممکن نشد|عکس نمایه|حساب Google|تغییرات با نشست شما محافظت می‌شوند|نام کاربری هر هفت روز یک بار تغییر می‌کند",
        "hi" to "प्रोफ़ाइल संपादित करें|आपकी प्रोफ़ाइल|दिखने वाला नाम|विशिष्ट उपयोगकर्ता नाम|फ़ोटो बदलें|फ़ोटो हटाएँ|बदलाव सहेजें|रद्द करें|प्रोफ़ाइल अपडेट हुई|उपयोगकर्ता नाम पहले से है|बदलने के लिए फिर लॉग इन करें|अमान्य नाम या उपयोगकर्ता नाम|फ़ोटो संसाधित नहीं हुई|प्रोफ़ाइल फ़ोटो|Google खाता|बदलाव आपके सत्र से सुरक्षित हैं|नाम हर सात दिन में एक बार बदलें",
        "ja" to "プロフィール編集|プロフィール|表示名|固有のユーザー名|写真を変更|写真を削除|変更を保存|キャンセル|更新しました|ユーザー名は使用済みです|再ログインして編集|名前かユーザー名が無効|写真を処理できません|プロフィール写真|Google アカウント|変更はセッションで保護されます|ユーザー名の変更は7日に1回です",
        "id" to "Edit profil|Profil Anda|Nama tampilan|Nama pengguna unik|Ubah foto|Hapus foto|Simpan perubahan|Batal|Profil diperbarui|Nama pengguna sudah dipakai|Masuk lagi untuk mengedit|Nama atau pengguna tidak valid|Foto gagal diproses|Foto profil|Akun Google|Perubahan dilindungi oleh sesi Anda|Nama pengguna bisa diubah tiap tujuh hari",
        "vi" to "Chỉnh sửa hồ sơ|Hồ sơ của bạn|Tên hiển thị|Tên người dùng duy nhất|Đổi ảnh|Xóa ảnh|Lưu thay đổi|Hủy|Đã cập nhật hồ sơ|Tên người dùng đã có|Đăng nhập lại để sửa|Tên hoặc người dùng không hợp lệ|Không xử lý được ảnh|Ảnh hồ sơ|Tài khoản Google|Thay đổi được bảo vệ bởi phiên đăng nhập|Chỉ đổi tên người dùng mỗi bảy ngày"
    ).mapValues{it.value.split("|")}
    fun get(locale:String,key:String):String {
        val index=labels.indexOf(key)
        if(index<0)return key
        return when(locale.lowercase(Locale.ROOT)){
            "es"->es[index]
            "in"->languages["id"]?.getOrNull(index)?:key
            else->languages[locale.lowercase(Locale.ROOT)]?.getOrNull(index)?:key
        }
    }
}

private val profileWhite=Color(0xFFF8F8F8)
private val profileMute=Color(0xFFAAAAAA)
private val profilePanel=Color(0xFF1E1E1E)
private val profileGreen=Color(0xFFB8DCC0)

private object AvatarPicture {
    suspend fun read(urlOrData:String?):Bitmap?=withContext(Dispatchers.IO){
        if(urlOrData.isNullOrBlank())return@withContext null
        val bytes=try {
            when {
                urlOrData.startsWith("data:image/jpeg;base64,") -> {
                    val data=urlOrData.substringAfter(',')
                    if(data.length>115000)return@withContext null
                    Base64.decode(data,Base64.DEFAULT)
                }
                urlOrData.startsWith("https://") -> {
                    val url=URL(urlOrData)
                    if(url.protocol!="https" ||
                        !Regex("lh[3-6]\\.googleusercontent\\.com")
                            .matches(url.host.lowercase(Locale.ROOT)))return@withContext null
                    val connection=url.openConnection() as HttpURLConnection
                    try{
                        connection.connectTimeout=5000
                        connection.readTimeout=5000
                        connection.instanceFollowRedirects=false
                        if(connection.responseCode!=200)return@withContext null
                        val out=ByteArrayOutputStream()
                        connection.inputStream.use{input->
                            val buffer=ByteArray(4096)
                            while(true){
                                val n=input.read(buffer)
                                if(n<0)break
                                if(out.size()+n>256*1024)return@withContext null
                                out.write(buffer,0,n)
                            }
                        }
                        out.toByteArray()
                    }finally{connection.disconnect()}
                }
                else -> return@withContext null
            }
        }catch(_:Exception){return@withContext null}
        BitmapFactory.decodeByteArray(bytes,0,bytes.size)
    }
    suspend fun encode(context:Context,uri:Uri):String?=withContext(Dispatchers.IO){
        try{
            val bounds=BitmapFactory.Options().apply{inJustDecodeBounds=true}
            val boundsStream=context.contentResolver.openInputStream(uri)?:return@withContext null
            boundsStream.use{ BitmapFactory.decodeStream(it,null,bounds) }
            val width=bounds.outWidth
            val height=bounds.outHeight
            if(width !in 1..10000||height !in 1..10000)return@withContext null
            var sample=1
            while(max(width,height)/sample>480)sample*=2
            val opts=BitmapFactory.Options().apply{inSampleSize=sample}
            val source=context.contentResolver.openInputStream(uri)?.use{
                BitmapFactory.decodeStream(it,null,opts)
            }?:return@withContext null
            val ratio=minOf(1f,320f/max(source.width,source.height))
            val picture=Bitmap.createScaledBitmap(source,
                max(1,(source.width*ratio).toInt()),max(1,(source.height*ratio).toInt()),true)
            if(picture!==source)source.recycle()
            var output:ByteArray?=null
            for(quality in listOf(85,75,65,55,45,35)){
                val out=ByteArrayOutputStream()
                picture.compress(Bitmap.CompressFormat.JPEG,quality,out)
                if(out.size()<=70*1024){output=out.toByteArray();break}
            }
            picture.recycle()
            output?.let{"data:image/jpeg;base64,"+
                Base64.encodeToString(it,Base64.NO_WRAP)}
        }catch(_:Exception){null}
    }
}

@Composable
internal fun CommerceAvatar(avatar:String?,modifier:Modifier=Modifier.size(64.dp)) {
    val bitmap by produceState<Bitmap?>(null,avatar) {value=AvatarPicture.read(avatar)}
    Box(modifier.clip(CircleShape).background(Color(0xFF353535))
        .border(1.dp,Color(0xFF5C5C5C),CircleShape),
        contentAlignment=Alignment.Center){
        if(bitmap!=null)Image(bitmap!!.asImageBitmap(),null,
            modifier=Modifier.fillMaxSize(),contentScale=ContentScale.Crop)
        else Icon(Icons.Outlined.AccountCircle,null,tint=profileWhite,
            modifier=Modifier.fillMaxSize().padding(10.dp))
    }
}

@Composable
internal fun CommerceAccountHero(language:String,user:CommerceIdentity?,
    onSignIn:()->Unit,onEdit:()->Unit,onSignOut:()->Unit){
    val label:(String)->String={CommerceProfileText.get(language,it)}
    Column(Modifier.fillMaxWidth().background(profilePanel,RoundedCornerShape(25.dp))
        .padding(20.dp),verticalArrangement=Arrangement.spacedBy(15.dp)){
        Row(verticalAlignment=Alignment.CenterVertically,
            horizontalArrangement=Arrangement.spacedBy(15.dp)){
            CommerceAvatar(user?.avatar,Modifier.size(86.dp))
            Column(Modifier.weight(1f),verticalArrangement=Arrangement.spacedBy(5.dp)){
                Text(user?.name?.takeIf{it.isNotBlank()}?:CommerceI18n.translate(language,
                    "Invitado","Guest"),color=profileWhite,fontSize=21.sp,
                    fontWeight=FontWeight.Bold,maxLines=2)
                if(user!=null){
                    Text("@"+user.username,color=profileGreen,fontSize=13.sp,
                        maxLines=1,overflow=TextOverflow.Ellipsis)
                    Text(user.email,color=profileMute,fontSize=12.sp,
                        maxLines=1,overflow=TextOverflow.Ellipsis)
                }
            }
        }
        Surface(color=Color(0xFF26372B),shape=RoundedCornerShape(14.dp)){
            Row(Modifier.padding(horizontal=13.dp,vertical=9.dp),
                verticalAlignment=Alignment.CenterVertically){
                Icon(Icons.Outlined.VerifiedUser,null,tint=profileGreen,
                    modifier=Modifier.size(18.dp))
                Spacer(Modifier.width(8.dp))
                Text(label("Google account"),fontSize=12.sp,color=profileGreen)
            }
        }
        if(user==null)Button(onClick=onSignIn,modifier=Modifier.fillMaxWidth(),
            colors=ButtonDefaults.buttonColors(containerColor=profileWhite,
                contentColor=Color.Black)){
            Text(CommerceI18n.translate(language,"Iniciar sesión","Sign in"))
        }else{
            Button(onClick=onEdit,modifier=Modifier.fillMaxWidth(),
                colors=ButtonDefaults.buttonColors(containerColor=profileWhite,
                    contentColor=Color.Black)){
                Icon(Icons.Outlined.Edit,null)
                Spacer(Modifier.width(9.dp))
                Text(label("Edit profile"))
            }

        }
    }
}

@Composable
internal fun CommerceProfileEditor(language:String,auth:NativeCommerceAuth,
    user:CommerceIdentity?,onCancel:()->Unit,onSaved:(JSONObject)->Unit){
    val context=LocalContext.current
    val scope=rememberCoroutineScope()
    val tr:(String)->String={CommerceProfileText.get(language,it)}
    var displayName by remember(user?.id){mutableStateOf(user?.name.orEmpty())}
    var username by remember(user?.id){mutableStateOf(user?.username.orEmpty())}
    var photo by remember(user?.id){mutableStateOf<String?>(null)}
    var replacePhoto by remember(user?.id){mutableStateOf(false)}
    var saving by remember{mutableStateOf(false)}
    var preparing by remember{mutableStateOf(false)}
    var notice by remember{mutableStateOf<String?>(null)}
    val launcher=rememberLauncherForActivityResult(ActivityResultContracts.GetContent()){uri->
        if(uri!=null && !saving)scope.launch{
            preparing=true
            try{
                val encoded=AvatarPicture.encode(context,uri)
                if(encoded==null)notice=tr("Photo could not be processed")
                else{photo=encoded;replacePhoto=true;notice=null}
            }finally{preparing=false}
        }
    }
    val normalizedName=displayName.trim()
    val normalizedUser=username.trim().lowercase(Locale.ROOT)
    val valid=NativeProfileRules.validDisplayName(normalizedName) &&
        NativeProfileRules.validUsername(normalizedUser)
    Column(verticalArrangement=Arrangement.spacedBy(17.dp)){
        Text(tr("Your profile"),color=profileWhite,fontSize=27.sp,
            fontWeight=FontWeight.Bold)
        Card(colors=CardDefaults.cardColors(containerColor=profilePanel),
            shape=RoundedCornerShape(24.dp),modifier=Modifier.fillMaxWidth()){
            Column(Modifier.padding(20.dp),horizontalAlignment=Alignment.CenterHorizontally,
                verticalArrangement=Arrangement.spacedBy(12.dp)){
                CommerceAvatar(if(replacePhoto)photo else user?.avatar,Modifier.size(104.dp))
                Text(tr("Profile photo"),color=profileWhite,fontWeight=FontWeight.SemiBold)
                Row(horizontalArrangement=Arrangement.spacedBy(9.dp)){
                    OutlinedButton(enabled=!preparing&&!saving,onClick={launcher.launch("image/*")}){
                        Icon(Icons.Outlined.PhotoCamera,null,Modifier.size(18.dp))
                        Spacer(Modifier.width(6.dp))
                        Text(tr("Change photo"),fontSize=12.sp)
                    }
                    OutlinedButton(enabled=!preparing&&!saving,
                        onClick={photo=null;replacePhoto=true}){
                        Text(tr("Remove photo"),fontSize=12.sp)
                    }
                }
                if(preparing)LinearProgressIndicator(Modifier.fillMaxWidth(),color=profileGreen)
            }
        }
        OutlinedTextField(displayName,{displayName=it.take(100)},singleLine=true,
            label={Text(tr("Display name"))},modifier=Modifier.fillMaxWidth(),
            colors=OutlinedTextFieldDefaults.colors(
                focusedTextColor=profileWhite,unfocusedTextColor=profileWhite))
        OutlinedTextField(username,{username=it.take(30)},singleLine=true,
            label={Text(tr("Unique username"))},prefix={Text("@")},
            modifier=Modifier.fillMaxWidth(),
            colors=OutlinedTextFieldDefaults.colors(
                focusedTextColor=profileWhite,unfocusedTextColor=profileWhite))
        Text(tr("Username changes are allowed once every seven days"),
            color=profileMute,fontSize=12.sp)
        if(!valid)Text(tr("Invalid name or username"),
            color=Color(0xFFFFB9B9),fontSize=12.sp)
        Text(tr("Your changes are protected by your account session"),
            color=profileMute,fontSize=12.sp)
        if(notice!=null)Text(notice.orEmpty(),color=Color(0xFFEAC8A0),fontSize=13.sp)
        Button(enabled=user!=null&&valid&&!saving&&!preparing,
            modifier=Modifier.fillMaxWidth(),onClick={
                scope.launch {
                    saving=true;notice=null
                    try{
                        onSaved(auth.editProfile(normalizedName,normalizedUser,photo,replacePhoto))
                    }catch(e:kotlinx.coroutines.CancellationException){throw e}
                    catch(e:Exception){
                        val code=NativeCommerceAuth.diagnostic(e)
                        notice=when(code){
                            "USERNAME_TAKEN"->tr("Username taken")
                            "HANDLE_CHANGE_LIMIT"->tr("Username changes are allowed once every seven days")
                            "REAUTHENTICATION_REQUIRED","SIGN_IN_REQUIRED"->tr("Sign in again to edit")
                            "INVALID_PROFILE"->tr("Invalid name or username")
                            "INVALID_AVATAR"->tr("Photo could not be processed")
                            else->code
                        }
                    }finally{saving=false}
                }
            },
            colors=ButtonDefaults.buttonColors(containerColor=profileWhite,
                contentColor=Color.Black)){
            Icon(Icons.Outlined.Check,null)
            Spacer(Modifier.width(8.dp))
            Text(tr("Save changes"))
        }
        OutlinedButton(onClick=onCancel,modifier=Modifier.fillMaxWidth(),
            enabled=!saving){Text(tr("Cancel"))}
    }
}
