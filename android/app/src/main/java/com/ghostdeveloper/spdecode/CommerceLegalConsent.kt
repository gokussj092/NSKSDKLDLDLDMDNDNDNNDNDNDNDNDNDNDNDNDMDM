package com.ghostdeveloper.spdecode

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.text.ClickableText
import androidx.compose.material3.Checkbox
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.SpanStyle
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.buildAnnotatedString
import androidx.compose.ui.text.style.TextDecoration
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp

/**
 * A single, accessible consent row. The translated terms and privacy words
 * are clickable inline, without duplicate footer links or repeated copy.
 */
internal object CommerceLegalConsent {
    fun text(language:String)=buildAnnotatedString {
        val sentence=CommerceI18n.policyConsent(language)
        append(sentence)
        // Highlight the entire legal phrase, not just one isolated word.
        // This avoids multiple consent paragraphs or separate legal buttons.
        val phrases=when(language.lowercase()) {
            "es" -> "términos del servicio" to "política de privacidad"
            "pt" -> "termos de serviço" to "política de privacidade"
            "fr" -> "conditions d'utilisation" to "politique de confidentialité"
            "de" -> "Nutzungsbedingungen" to "Datenschutzerklärung"
            "it" -> "termini di servizio" to "informativa sulla privacy"
            "tr" -> "Hizmet şartlarını" to "gizlilik politikasını"
            "ru" -> "условия обслуживания" to "политику конфиденциальности"
            "ar" -> "شروط الخدمة" to "سياسة الخصوصية"
            "fa" -> "شرایط خدمات" to "سیاست حفظ حریم خصوصی"
            "hi" -> "सेवा की शर्तों" to "गोपनीयता नीति"
            "ja" -> "利用規約" to "プライバシーポリシー"
            "id","in" -> "ketentuan layanan" to "kebijakan privasi"
            "vi" -> "điều khoản dịch vụ" to "chính sách quyền riêng tư"
            else -> "Terms of Service" to "Privacy Policy"
        }
        for((tag,term) in listOf("terms" to phrases.first,"privacy" to phrases.second)) {
            val index=sentence.indexOf(term,ignoreCase=true)
            if(index>=0) {
                addStyle(SpanStyle(color=Color(0xFFE7E7E7),
                    textDecoration=TextDecoration.Underline),index,index+term.length)
                addStringAnnotation("legal",tag,index,index+term.length)
            }
        }
    }
}

@Composable
internal fun CommerceConsentRow(
    language:String,accepted:Boolean,onAccepted:(Boolean)->Unit,
    onLegalLink:(String)->Unit
){
    Row(Modifier.fillMaxWidth(),verticalAlignment=Alignment.CenterVertically) {
        Checkbox(checked=accepted,onCheckedChange=onAccepted,
            modifier=Modifier.size(45.dp))
        val annotated=CommerceLegalConsent.text(language)
        ClickableText(
            text=annotated,
            modifier=Modifier.weight(1f).padding(start=4.dp,top=5.dp,bottom=5.dp),
            style=TextStyle(color=Color(0xFFB0B0B0),fontSize=12.sp,lineHeight=18.sp),
            onClick={offset->
                annotated.getStringAnnotations("legal",offset,offset)
                    .firstOrNull()?.item?.let(onLegalLink)
            }
        )
    }
}
