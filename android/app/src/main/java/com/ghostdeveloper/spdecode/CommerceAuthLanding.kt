package com.ghostdeveloper.spdecode

import android.widget.ImageView
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.MailOutline
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.runtime.saveable.rememberSaveable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.viewinterop.AndroidView
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

private object AuthLandingLanguage {
    private val keys=listOf("Welcome back","Create your account","Sign in to continue",
        "Join SP-DECODE with your Google account","Sign in","Create account",
        "Access your account","Create with Google","Continue with Google",
        "Create account with Google","or with email","Email and password",
        "Your account and purchases are securely linked.")
    private val translated=mapOf(
        "pt" to "Bem-vindo de volta|Crie sua conta|Entre para continuar|Entre no SP-DECODE com sua conta Google|Entrar|Criar conta|Acessar sua conta|Criar com Google|Continuar com Google|Criar conta com Google|ou com e-mail|E-mail e senha|Sua conta e compras estão vinculadas com segurança.",
        "fr" to "Bon retour|Créez votre compte|Connectez-vous pour continuer|Rejoignez SP-DECODE avec Google|Connexion|Créer un compte|Accéder à votre compte|Créer avec Google|Continuer avec Google|Créer avec Google|ou par e-mail|E-mail et mot de passe|Votre compte et vos achats sont liés en toute sécurité.",
        "de" to "Willkommen zurück|Erstelle dein Konto|Zum Fortfahren anmelden|Tritt SP-DECODE mit deinem Google-Konto bei|Anmelden|Konto erstellen|Auf dein Konto zugreifen|Mit Google erstellen|Mit Google fortfahren|Google-Konto erstellen|oder per E-Mail|E-Mail und Passwort|Dein Konto und deine Käufe sind sicher verknüpft.",
        "it" to "Bentornato|Crea il tuo account|Accedi per continuare|Unisciti a SP-DECODE con Google|Accedi|Crea account|Accedi al tuo account|Crea con Google|Continua con Google|Crea account con Google|oppure con e-mail|E-mail e password|Il tuo account e gli acquisti sono collegati in modo sicuro.",
        "tr" to "Tekrar hoş geldin|Hesabını oluştur|Devam etmek için giriş yap|Google hesabınla SP-DECODE'a katıl|Giriş yap|Hesap oluştur|Hesabına eriş|Google ile oluştur|Google ile devam et|Google ile hesap oluştur|veya e-posta ile|E-posta ve şifre|Hesabın ve satın alımların güvenle bağlı.",
        "ru" to "С возвращением|Создайте аккаунт|Войдите, чтобы продолжить|Присоединяйтесь к SP-DECODE через Google|Войти|Создать аккаунт|Войти в аккаунт|Создать через Google|Продолжить с Google|Создать аккаунт Google|или по почте|Почта и пароль|Аккаунт и покупки надёжно связаны.",
        "ar" to "مرحبًا بعودتك|أنشئ حسابك|سجل الدخول للمتابعة|انضم إلى SP-DECODE بحساب Google|تسجيل الدخول|إنشاء حساب|الوصول إلى حسابك|الإنشاء باستخدام Google|المتابعة باستخدام Google|إنشاء حساب عبر Google|أو بالبريد الإلكتروني|البريد وكلمة المرور|حسابك ومشترياتك مرتبطان بأمان.",
        "fa" to "خوش آمدید|حساب خود را بسازید|برای ادامه وارد شوید|با حساب گوگل به SP-DECODE بپیوندید|ورود|ایجاد حساب|دسترسی به حساب|ساخت با گوگل|ادامه با گوگل|ساخت حساب با گوگل|یا با ایمیل|ایمیل و رمز عبور|حساب و خریدهای شما به‌طور امن متصل‌اند.",
        "hi" to "वापसी पर स्वागत है|अपना खाता बनाएँ|जारी रखने के लिए लॉगिन करें|Google खाते से SP-DECODE से जुड़ें|लॉगिन|खाता बनाएँ|अपने खाते में जाएँ|Google से बनाएँ|Google से जारी रखें|Google से खाता बनाएँ|या ईमेल से|ईमेल और पासवर्ड|आपका खाता और खरीदारी सुरक्षित रूप से जुड़े हैं।",
        "ja" to "おかえりなさい|アカウントを作成|ログインして続行|GoogleアカウントでSP-DECODEに登録|ログイン|アカウント作成|アカウントにアクセス|Googleで作成|Googleで続行|Googleでアカウント作成|またはメールで|メールとパスワード|アカウントと購入履歴は安全に関連付けられています。",
        "id" to "Selamat datang kembali|Buat akun Anda|Masuk untuk melanjutkan|Bergabung dengan SP-DECODE menggunakan Google|Masuk|Buat akun|Akses akun Anda|Buat dengan Google|Lanjutkan dengan Google|Buat akun dengan Google|atau dengan email|Email dan kata sandi|Akun dan pembelian Anda terhubung secara aman.",
        "vi" to "Chào mừng trở lại|Tạo tài khoản|Đăng nhập để tiếp tục|Tham gia SP-DECODE bằng tài khoản Google|Đăng nhập|Tạo tài khoản|Truy cập tài khoản|Tạo bằng Google|Tiếp tục với Google|Tạo tài khoản với Google|hoặc qua email|Email và mật khẩu|Tài khoản và giao dịch được liên kết an toàn."
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

/** The real packaged launcher resource is the identity on this screen. */
@Composable
internal fun CommerceAuthLanding(language:String,accepted:Boolean,
    busy:Boolean,error:String?,onAccepted:(Boolean)->Unit,
    onLegalLink:(String)->Unit,onGoogle:()->Unit,onEmail:()->Unit){
    val t:(String,String)->String={es,en->AuthLandingLanguage.text(language,es,en)}
    val bg=Color(0xFF222222)
    val selected=Color(0xFFF7F7F7)
    val secondary=Color(0xFFB3B3B3)
    var mode by rememberSaveable{mutableIntStateOf(0)}
    Column(Modifier.fillMaxWidth().padding(top=10.dp,bottom=25.dp),
        horizontalAlignment=Alignment.CenterHorizontally,
        verticalArrangement=Arrangement.spacedBy(14.dp)){
        Box(Modifier.size(100.dp)
            .background(bg,RoundedCornerShape(27.dp))
            .border(1.dp,Color(0xFF484848),RoundedCornerShape(27.dp)),
            contentAlignment=Alignment.Center){
            // Android's launcher resource can be an adaptive-icon XML on API 26+.
            // painterResource() supports vector/raster drawables, not adaptive icons.
            // Let ImageView render the actual installed application icon instead.
            AndroidView(
                factory={ctx->
                    ImageView(ctx).apply{
                        scaleType=ImageView.ScaleType.FIT_CENTER
                        val installedIcon=runCatching{
                            ctx.packageManager.getApplicationIcon(ctx.packageName)
                        }.getOrNull()
                        if(installedIcon!=null)setImageDrawable(installedIcon)
                        else setImageResource(R.drawable.ic_launcher_foreground)
                    }
                },
                modifier=Modifier.size(82.dp)
            )
        }
        Text("SP-DECODE",color=selected,fontSize=21.sp,fontWeight=FontWeight.Bold)
        Text(if(mode==0)t("Bienvenido de nuevo","Welcome back")
                 else t("Crea tu cuenta","Create your account"),
            color=selected,fontSize=29.sp,fontWeight=FontWeight.Bold,
            textAlign=TextAlign.Center)
        Text(if(mode==0)t("Inicia sesión para continuar",
                "Sign in to continue")
             else t("Únete a SP-DECODE con tu cuenta de Google",
                "Join SP-DECODE with your Google account"),
            color=secondary,fontSize=14.sp,textAlign=TextAlign.Center)
        Spacer(Modifier.height(10.dp))
        Column(Modifier.fillMaxWidth()
            .background(bg,RoundedCornerShape(25.dp)).padding(18.dp),
            verticalArrangement=Arrangement.spacedBy(17.dp)){
            Row(Modifier.fillMaxWidth()
                .background(Color(0xFF151515),RoundedCornerShape(18.dp)).padding(4.dp),
                horizontalArrangement=Arrangement.spacedBy(5.dp)){
                listOf(t("Iniciar sesión","Sign in"),
                    t("Crear cuenta","Create account")).forEachIndexed{index,label->
                    Box(Modifier.weight(1f)
                        .clip(RoundedCornerShape(14.dp))
                        .background(if(mode==index)selected else Color.Transparent)
                        .clickable(enabled=!busy){mode=index}
                        .padding(vertical=14.dp),
                        contentAlignment=Alignment.Center){
                        Text(label,color=if(mode==index)Color.Black else secondary,
                            fontWeight=FontWeight.SemiBold,fontSize=13.sp,
                            textAlign=TextAlign.Center,maxLines=1)
                    }
                }
            }
            Text(if(mode==0)t("Accede a tu cuenta","Access your account")
                   else t("Registrarse con Google","Create with Google"),
                color=selected,fontWeight=FontWeight.SemiBold,fontSize=17.sp)
            OutlinedButton(onClick=onGoogle,enabled=accepted&&!busy,
                modifier=Modifier.fillMaxWidth().heightIn(min=53.dp),
                shape=RoundedCornerShape(16.dp),
                border=androidx.compose.foundation.BorderStroke(1.dp,Color(0xFF686868))){
                Box(Modifier.size(28.dp).background(Color.White,RoundedCornerShape(50)),
                    contentAlignment=Alignment.Center){
                    Text("G",color=Color(0xFF4285F4),fontSize=19.sp,
                        fontWeight=FontWeight.Bold)
                }
                Spacer(Modifier.width(11.dp))
                Text(if(mode==0)t("Continuar con Google","Continue with Google")
                     else t("Crear cuenta con Google","Create account with Google"),
                    color=selected,fontWeight=FontWeight.Medium)
            }
            if(mode==0){
                Row(Modifier.fillMaxWidth(),verticalAlignment=Alignment.CenterVertically,
                    horizontalArrangement=Arrangement.spacedBy(11.dp)){
                    HorizontalDivider(modifier=Modifier.weight(1f),color=Color(0xFF515151))
                    Text(t("o con correo","or with email"),color=secondary,fontSize=12.sp)
                    HorizontalDivider(modifier=Modifier.weight(1f),color=Color(0xFF515151))
                }
                OutlinedButton(onClick=onEmail,enabled=!busy,
                    modifier=Modifier.fillMaxWidth().heightIn(min=53.dp),
                    shape=RoundedCornerShape(16.dp),
                    border=androidx.compose.foundation.BorderStroke(1.dp,Color(0xFF686868))){
                    Icon(Icons.Outlined.MailOutline,null,tint=selected)
                    Spacer(Modifier.width(11.dp))
                    Text(t("Correo y contraseña","Email and password"),color=selected,
                        fontWeight=FontWeight.Medium)
                }
            }
            CommerceConsentRow(language,accepted,onAccepted,onLegalLink)
            if(busy)LinearProgressIndicator(modifier=Modifier.fillMaxWidth(),
                color=Color(0xFFB8DCC0))
            if(error!=null)Text(error,color=Color(0xFFFF7777),
                fontSize=12.sp,lineHeight=18.sp)
        }
        Text(t("Tu cuenta y compras están vinculadas de forma segura.",
            "Your account and purchases are securely linked."),
            color=secondary,fontSize=12.sp,textAlign=TextAlign.Center)
    }
}
