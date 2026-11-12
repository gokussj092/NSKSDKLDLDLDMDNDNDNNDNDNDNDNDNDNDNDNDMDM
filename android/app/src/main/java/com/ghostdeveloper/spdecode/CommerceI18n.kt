package com.ghostdeveloper.spdecode

/**
 * Localized native-commerce strings. Lookup keys are stable English UI copy.
 * Rendering uses Activity.resources.locale to respect SP-DECODE's own picker.
 * See CommerceLanguageData for translations into every shipped app locale.
 */
internal object CommerceI18n {
    internal val keys=listOf(
        "Back",
        "My account",
        "Secure sign in",
        "Your cart",
        "Store",
        "Cart",
        "CREDITS / APK ANALYSIS",
        "Analysis credits",
        "One credit covers one eligible APK/APKS analysis. Normal VPN file decoding does not use these credits.",
        "Choose a pack",
        "credits",
        "Save ",
        "No published USD credit packs.",
        "Packs",
        "total credits",
        "Total",
        "Add to cart",
        "APK credits",
        "USD prices received from the server. Purchasing requires session and quote verification.",
        "Commercial API",
        "Use decoding methods from your server with an API key bound to an authorized public IP.",
        "Included services",
        "File decoding",
        "Text decoding",
        "Online methods",
        "Catalog decoding",
        "APK/APKS application analysis is not included",
        "License duration",
        "days",
        "No published USD prices for the API.",
        "Public server IP (optional at purchase)",
        "Public IPv4 or IPv6",
        "Enter a valid public IP; private, local and domain values are not accepted.",
        "You may buy without an IP, then bind a public server IP from My account before the key can be used. You may change it later.",
        "Add API to cart",
        "EXPERIENCE / SP-DECODE",
        "Remove ads",
        "30 days without ads inside the app",
        "No interstitial ads",
        "Applies to your active account",
        "Does not include APK credits or API access. No automatic renewal in this proposal.",
        "Coming soon",
        "SP-DECODE SERVICES",
        "Everything for your projects.",
        "Credits, API and an ad-free experience.",
        "Loading server prices…",
        "Catalog unavailable. No invented prices will be shown.",
        "Official USD prices from the server. Checkout requires a verified session and quote.",
        "Browse products",
        "APK/APKS analysis and technical results",
        "No USD price available",
        "Details",
        "Files, text, online methods and catalogs",
        "One month without ads",
        "Support & billing",
        "Your account will display orders, receipts, balances, terms and keys when commerce services are enabled.",
        "Order summary",
        "Your cart is empty.",
        "Authorized IP: ",
        "Remove",
        "Subtotal",
        "Reference prices only; taxes, discounts, availability and final payment require a server quote.",
        "Checkout not enabled",
        "Account center",
        "Guest",
        "No linked session",
        "Sign in",
        "Sign out",
        "Orders",
        "Security",
        "Overview",
        "Order history",
        "Invoices, orders and confirmed payments will appear after sign-in.",
        "My API keys",
        "View limits and quota",
        "Review authorized IP",
        "Rotate or revoke key",
        "A key is shown only for a verified license. It is never stored in plain text in the app.",
        "Bound public IP",
        "New public IP",
        "Update authorized IP",
        "Public IP updated",
        "Cannot update IP. Sign in again if required.",
        "Your purchased API will appear here to configure or change its public IP.",
        "Security & credentials",
        "Google-linked account",
        "Add or change password",
        "The server currently supports Google only. Password support requires identity verification, recovery and safe account linking.",
        "My services",
        "APK credit balance",
        "Available after sign-in",
        "Licenses, terms and IP",
        "Status and expiration",
        "Open store",
        "Access your account inside the app",
        "Create account",
        "Choose how to continue",
        "Sign in failed. Verify account server and Google OAuth configuration.",
        "Continue with Google",
        "or by email",
        "Continue with email",
        "Email address",
        "Password",
        "Password sign-in is not yet enabled on the server. These values will not be sent or stored.",
        "Other sign-in methods",
        "The profile stays inside SP-DECODE. Google identity uses Android's approved secure flow, not an embedded fake Google login form.",
        "Account password",
        "This feature requires secure server support to add, change and recover passwords while keeping Google account linking intact. No credentials have been changed.",
        "OK",
    )
    fun policyConsent(locale:String):String=when(locale.lowercase()){
        "es"->"Acepto los términos del servicio y la política de privacidad."
        "pt"->"Aceito os termos de serviço e a política de privacidade."
        "fr"->"J'accepte les conditions d'utilisation et la politique de confidentialité."
        "de"->"Ich akzeptiere die Nutzungsbedingungen und die Datenschutzerklärung."
        "it"->"Accetto i termini di servizio e l'informativa sulla privacy."
        "tr"->"Hizmet şartlarını ve gizlilik politikasını kabul ediyorum."
        "ru"->"Я принимаю условия обслуживания и политику конфиденциальности."
        "ar"->"أوافق على شروط الخدمة وسياسة الخصوصية."
        "fa"->"شرایط خدمات و سیاست حفظ حریم خصوصی را می‌پذیرم."
        "hi"->"मैं सेवा की शर्तों और गोपनीयता नीति से सहमत हूँ।"
        "ja"->"利用規約とプライバシーポリシーに同意します。"
        "id","in"->"Saya menyetujui ketentuan layanan dan kebijakan privasi."
        "vi"->"Tôi đồng ý với điều khoản dịch vụ và chính sách quyền riêng tư."
        else->"I agree to the Terms of Service and Privacy Policy."
    }
    fun termsLabel(locale:String):String=when(locale.lowercase()){
        "es"->"Términos";"pt"->"Termos";"fr"->"Conditions";"de"->"Bedingungen"
        "it"->"Termini";"tr"->"Şartlar";"ru"->"Условия";"ar"->"الشروط"
        "fa"->"شرایط";"hi"->"शर्तें";"ja"->"利用規約";"id","in"->"Ketentuan"
        "vi"->"Điều khoản";else->"Terms"
    }
    fun privacyLabel(locale:String):String=when(locale.lowercase()){
        "es"->"Privacidad";"pt"->"Privacidade";"fr"->"Confidentialité";"de"->"Datenschutz"
        "it"->"Privacy";"tr"->"Gizlilik";"ru"->"Конфиденциальность";"ar"->"الخصوصية"
        "fa"->"حریم خصوصی";"hi"->"गोपनीयता";"ja"->"プライバシー";"id","in"->"Privasi"
        "vi"->"Quyền riêng tư";else->"Privacy"
    }
    fun translate(locale:String,es:String,en:String):String{
        val normalized=when(locale.lowercase()){
            "in"->"id"
            else->locale.lowercase()
        }
        if(normalized=="es")return es
        if(normalized=="en")return en
        val n=keys.indexOf(en)
        if(n<0)return en
        return CommerceLanguageData.value(normalized,n)?:en
    }
}
