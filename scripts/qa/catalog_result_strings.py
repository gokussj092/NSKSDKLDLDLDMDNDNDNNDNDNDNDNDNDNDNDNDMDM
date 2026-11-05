#!/usr/bin/env python3
"""Idempotent additions for the existing fourteen approved resource locales."""
import re
from pathlib import Path
from xml.sax.saxutils import escape
KEYS=['catalog_transfer_verifying','result_engine_error','result_previous_page','result_copy_too_large','catalog_transfer_paused','catalog_transfer_resume','catalog_transfer_discard','catalog_transfer_retention']
TEXT={
'values':['Verifying and saving…','Preview unavailable. The complete result remains available for export.','Previous page','The clipboard could not accept this result. Export the complete file instead.','Download interrupted','Retry / resume','Delete partial download','Verified fragments stay encrypted for up to 7 days for resuming.'],
'values-es':['Verificando y guardando…','Vista previa no disponible. El resultado completo sigue disponible para exportarlo.','Página anterior','El portapapeles no pudo aceptar el resultado. Exporta el archivo completo.','Descarga interrumpida','Reintentar / reanudar','Eliminar descarga parcial','Los fragmentos verificados se guardan cifrados hasta 7 días para reanudar.'],
'values-de':['Prüfen und speichern…','Vorschau nicht verfügbar. Das vollständige Ergebnis kann exportiert werden.','Vorherige Seite','Die Zwischenablage konnte das Ergebnis nicht aufnehmen. Exportiere die vollständige Datei.','Download unterbrochen','Erneut versuchen / fortsetzen','Teildownload löschen','Geprüfte Fragmente bleiben bis zu 7 Tage verschlüsselt gespeichert.'],
'values-fr':['Vérification et enregistrement…','Aperçu indisponible. Le résultat complet reste disponible à l’exportation.','Page précédente','Le presse-papiers ne peut pas recevoir ce résultat. Exportez le fichier complet.','Téléchargement interrompu','Réessayer / reprendre','Supprimer le téléchargement partiel','Les fragments vérifiés restent chiffrés pendant 7 jours au maximum.'],
'values-it':['Verifica e salvataggio…','Anteprima non disponibile. Il risultato completo può essere esportato.','Pagina precedente','Gli appunti non possono ricevere il risultato. Esporta il file completo.','Download interrotto','Riprova / riprendi','Elimina download parziale','I frammenti verificati restano cifrati per un massimo di 7 giorni.'],
'values-pt-rBR':['Verificando e salvando…','Prévia indisponível. O resultado completo continua disponível para exportação.','Página anterior','A área de transferência não aceitou o resultado. Exporte o arquivo completo.','Download interrompido','Tentar novamente / continuar','Excluir download parcial','Os fragmentos verificados ficam criptografados por até 7 dias.'],
'values-ru':['Проверка и сохранение…','Предпросмотр недоступен. Полный результат можно экспортировать.','Предыдущая страница','Буфер обмена не принял результат. Экспортируйте полный файл.','Загрузка прервана','Повторить / продолжить','Удалить частичную загрузку','Проверенные фрагменты хранятся зашифрованными до 7 дней.'],
'values-tr':['Doğrulanıyor ve kaydediliyor…','Önizleme kullanılamıyor. Tam sonuç dışa aktarılabilir.','Önceki sayfa','Pano sonucu kabul edemedi. Dosyanın tamamını dışa aktarın.','İndirme kesildi','Yeniden dene / sürdür','Kısmi indirmeyi sil','Doğrulanmış parçalar en fazla 7 gün şifreli olarak saklanır.'],
'values-in':['Memverifikasi dan menyimpan…','Pratinjau tidak tersedia. Hasil lengkap tetap dapat diekspor.','Halaman sebelumnya','Papan klip tidak dapat menerima hasil ini. Ekspor berkas lengkap.','Unduhan terputus','Coba lagi / lanjutkan','Hapus unduhan parsial','Fragmen terverifikasi disimpan terenkripsi hingga 7 hari.'],
'values-vi':['Đang xác minh và lưu…','Không có bản xem trước. Bạn vẫn có thể xuất toàn bộ kết quả.','Trang trước','Bảng nhớ tạm không nhận được kết quả. Hãy xuất toàn bộ tệp.','Tải xuống bị gián đoạn','Thử lại / tiếp tục','Xóa phần tải xuống','Các phần đã xác minh được lưu mã hóa tối đa 7 ngày.'],
'values-ja':['検証して保存しています…','プレビューを表示できません。結果全体はエクスポートできます。','前のページ','クリップボードに保存できませんでした。ファイル全体をエクスポートしてください。','ダウンロードが中断されました','再試行 / 再開','部分ダウンロードを削除','検証済みの断片は再開用に最大7日間暗号化して保存されます。'],
'values-ar':['جارٍ التحقق والحفظ…','المعاينة غير متاحة. لا تزال النتيجة الكاملة متاحة للتصدير.','الصفحة السابقة','تعذر نسخ النتيجة إلى الحافظة. صدّر الملف الكامل.','انقطع التنزيل','إعادة المحاولة / الاستئناف','حذف التنزيل الجزئي','تُحفظ الأجزاء المتحقق منها مشفرة لمدة تصل إلى 7 أيام.'],
'values-fa':['در حال بررسی و ذخیره…','پیش‌نمایش در دسترس نیست. نتیجه کامل همچنان قابل صدور است.','صفحه قبلی','حافظه موقت نتیجه را نپذیرفت. فایل کامل را صادر کنید.','دانلود قطع شد','تلاش دوباره / ادامه','حذف دانلود ناقص','بخش‌های تأییدشده تا ۷ روز به‌صورت رمزگذاری‌شده نگهداری می‌شوند.'],
'values-hi':['जाँच और सहेजना जारी है…','पूर्वावलोकन उपलब्ध नहीं है। पूरा परिणाम निर्यात किया जा सकता है।','पिछला पृष्ठ','क्लिपबोर्ड परिणाम स्वीकार नहीं कर सका। पूरी फ़ाइल निर्यात करें।','डाउनलोड बाधित हुआ','फिर कोशिश / जारी रखें','आंशिक डाउनलोड हटाएँ','सत्यापित भाग अधिकतम 7 दिनों तक एन्क्रिप्ट करके रखे जाते हैं।'],
}
def main():
 for locale,values in TEXT.items():
  p=Path('android/app/src/main/res')/locale/'strings.xml';s=p.read_text()
  for key,value in zip(KEYS,values):
   pattern=r'\s*<string name="'+key+r'"[^>]*>.*?</string>'
   s=re.sub(pattern,'',s,flags=re.S)
   s=s.replace('</resources>','    <string name="'+key+'">'+escape(value)+'</string>\n</resources>')
  for key,value in [('catalog_transfer_bytes_total','%1$s MiB / %2$s MiB'),('catalog_transfer_bytes_unknown','%1$s MiB')]:
   s=re.sub(r'(<string name="'+key+r'"[^>]*>).*?(</string>)',lambda m:m[1]+value+m[2],s,flags=re.S)
  p.write_text(s)
 print('Updated fourteen locales; verified catalog payload units are MiB.')
if __name__=='__main__':main()
