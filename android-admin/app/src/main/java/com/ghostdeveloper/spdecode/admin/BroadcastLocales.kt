package com.ghostdeveloper.spdecode.admin

// Matches the 14 locale resource directories of the existing Android client.
internal data class NoticeLanguage(val code: String, val name: String, val rtl: Boolean = false)

internal val noticeLanguages =
    listOf(
        NoticeLanguage("es", "Español"),
        NoticeLanguage("en", "English"),
        NoticeLanguage("pt-BR", "Português (Brasil)"),
        NoticeLanguage("fr", "Français"),
        NoticeLanguage("de", "Deutsch"),
        NoticeLanguage("it", "Italiano"),
        NoticeLanguage("ar", "العربية", true),
        NoticeLanguage("fa", "فارسی", true),
        NoticeLanguage("ru", "Русский"),
        NoticeLanguage("tr", "Türkçe"),
        NoticeLanguage("hi", "हिन्दी"),
        NoticeLanguage("id", "Bahasa Indonesia"),
        NoticeLanguage("vi", "Tiếng Việt"),
        NoticeLanguage("ja", "日本語"),
    )

internal fun defaultCatalogNotice(): Map<String, LocalizedNotice> =
    linkedMapOf(
        "es" to
            LocalizedNotice(
                "Nueva actualización disponible",
                "Ya puedes descargar la nueva versión del catálogo de SP-DECODE.",
            ),
        "en" to
            LocalizedNotice(
                "New update available",
                "You can now download the latest version of the SP-DECODE catalog.",
                "Update",
                "Cancel",
            ),
        "pt-BR" to
            LocalizedNotice(
                "Nova atualização disponível",
                "Você já pode baixar a nova versão do catálogo do SP-DECODE.",
                "Atualizar",
                "Cancelar",
            ),
        "fr" to
            LocalizedNotice(
                "Nouvelle mise à jour disponible",
                "Vous pouvez maintenant télécharger la nouvelle version du catalogue SP-DECODE.",
                "Mettre à jour",
                "Annuler",
            ),
        "de" to
            LocalizedNotice(
                "Neues Update verfügbar",
                "Du kannst jetzt die neue Version des SP-DECODE-Katalogs herunterladen.",
                "Aktualisieren",
                "Abbrechen",
            ),
        "it" to
            LocalizedNotice(
                "Nuovo aggiornamento disponibile",
                "Ora puoi scaricare la nuova versione del catalogo di SP-DECODE.",
                "Aggiorna",
                "Annulla",
            ),
        "ar" to
            LocalizedNotice(
                "يتوفر تحديث جديد",
                "يمكنك الآن تنزيل الإصدار الجديد من كتالوج SP-DECODE.",
                "تحديث",
                "إلغاء",
            ),
        "fa" to
            LocalizedNotice(
                "به‌روزرسانی جدید موجود است",
                "اکنون می‌توانید نسخه جدید فهرست SP-DECODE را دانلود کنید.",
                "به‌روزرسانی",
                "لغو",
            ),
        "ru" to
            LocalizedNotice(
                "Доступно новое обновление",
                "Теперь вы можете скачать новую версию каталога SP-DECODE.",
                "Обновить",
                "Отмена",
            ),
        "tr" to
            LocalizedNotice(
                "Yeni güncelleme mevcut",
                "SP-DECODE kataloğunun yeni sürümünü artık indirebilirsiniz.",
                "Güncelle",
                "İptal",
            ),
        "hi" to
            LocalizedNotice(
                "नया अपडेट उपलब्ध है",
                "अब आप SP-DECODE कैटलॉग का नया संस्करण डाउनलोड कर सकते हैं।",
                "अपडेट करें",
                "रद्द करें",
            ),
        "id" to
            LocalizedNotice(
                "Pembaruan baru tersedia",
                "Sekarang Anda dapat mengunduh versi terbaru katalog SP-DECODE.",
                "Perbarui",
                "Batal",
            ),
        "vi" to
            LocalizedNotice(
                "Có bản cập nhật mới",
                "Bạn có thể tải xuống phiên bản mới của danh mục SP-DECODE ngay bây giờ.",
                "Cập nhật",
                "Hủy",
            ),
        "ja" to
            LocalizedNotice("新しいアップデートがあります", "SP-DECODEカタログの新しいバージョンをダウンロードできます。", "更新", "キャンセル"),
    )
