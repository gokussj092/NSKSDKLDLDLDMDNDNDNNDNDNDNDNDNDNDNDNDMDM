package com.ghostdeveloper.spdecode

/** One extendable registry for settings and the accepted per-app language tag. */
data class SupportedLanguage(val tag:String,val nativeName:String)

object SupportedLanguages {
    val options:List<SupportedLanguage> = listOf(
        SupportedLanguage("system",""),
        SupportedLanguage("es","Español"),
        SupportedLanguage("en","English"),
        SupportedLanguage("pt-BR","Português (Brasil)"),
        SupportedLanguage("ar","العربية"),
        SupportedLanguage("fa","فارسی"),
        SupportedLanguage("fr","Français"),
        SupportedLanguage("id","Bahasa Indonesia"),
        SupportedLanguage("ru","Русский"),
        SupportedLanguage("de","Deutsch"),
        SupportedLanguage("tr","Türkçe"),
        SupportedLanguage("vi","Tiếng Việt"),
        SupportedLanguage("hi","हिन्दी"),
        SupportedLanguage("ja","日本語"),
        SupportedLanguage("it","Italiano"),
        SupportedLanguage("tl","Filipino"),
        SupportedLanguage("ur","اردو"),
        SupportedLanguage("bn","বাংলা"),
        SupportedLanguage("th","ไทย"),
        SupportedLanguage("am","አማርኛ"),
        SupportedLanguage("uk","Українська"),
        SupportedLanguage("ko","한국어"),
        SupportedLanguage("zh-CN","中文（简体）"),
        SupportedLanguage("ms","Bahasa Melayu"),
        SupportedLanguage("pl","Polski"),
        SupportedLanguage("ro","Română"),
        SupportedLanguage("sw","Kiswahili"),
        SupportedLanguage("ha","Hausa"),
        SupportedLanguage("ta","தமிழ்"),
        SupportedLanguage("my","မြန်မာ"),
        SupportedLanguage("km","ខ្មែរ"),
        SupportedLanguage("ne","नेपाली"),
        SupportedLanguage("uz","O‘zbekcha"),
        SupportedLanguage("sr","Српски"),
        SupportedLanguage("el","Ελληνικά"),
        SupportedLanguage("cs","Čeština"),
        SupportedLanguage("hu","Magyar"),
    )
    fun supports(tag:String):Boolean=options.any{it.tag==tag}
}
