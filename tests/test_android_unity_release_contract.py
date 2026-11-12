import pathlib
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


class AndroidUnityReleaseContract(unittest.TestCase):
    def test_production_apk_qa_only_coming_soon(self):
        app = read("android/app/src/main/java/com/ghostdeveloper/spdecode/SpDecodeApp.kt")
        gradle = read("android/app/build.gradle.kts")
        stub = read("android/app/src/comingSoon/java/com/ghostdeveloper/spdecode/cloud/CloudApkQaDisabled.kt")
        self.assertIn("2->if(BuildConfig.SPDECODE_APK_QA_ENABLED)", app)
        self.assertIn('exclude("com/ghostdeveloper/spdecode/cloud/CloudApkQaClient.kt")', gradle)
        self.assertIn('exclude("com/ghostdeveloper/spdecode/cloud/ApkQaWorker.kt")', gradle)
        self.assertIn('if(!enableQaBuild) from("src/comingSoon/java")', gradle)
        self.assertIn("APK_ANALYSIS_COMING_SOON", stub)
        self.assertNotIn("apkQaRequest(", stub)
        self.assertNotIn("/api/v1", stub)

    def test_ad_network_only_in_online_with_cmp(self):
        gradle = read("android/app/build.gradle.kts")
        host = read("android/app/src/unityAds/java/com/ghostdeveloper/spdecode/ads/UnityInterstitialHost.kt")
        activity = read("android/app/src/main/java/com/ghostdeveloper/spdecode/MainActivity.kt")
        self.assertIn("Unity Ads is Online-only", gradle)
        self.assertIn("SPDECODE_UNITY_UMP_APP_ID", gradle)
        self.assertIn("UserMessagingPlatform.loadAndShowConsentFormIfRequired", host)
        self.assertIn("consentInformation.canRequestAds()", host)
        self.assertEqual(activity.count("onlineAds?.onSavedResult("), 5)
        self.assertIn("ads_privacy_options", read("android/app/src/main/java/com/ghostdeveloper/spdecode/FunctionalSettingsPanel.kt"))

    def test_ads_retry_and_frequency_are_qa_safe(self):
        host = read("android/app/src/unityAds/java/com/ghostdeveloper/spdecode/ads/UnityInterstitialHost.kt")
        self.assertIn("MAX_DAILY_ADS=12", host)
        self.assertIn("MIN_INTERVAL_MS=240_000L", host)
        self.assertIn("LOAD_RETRY_MS=45_000L", host)
        self.assertIn("retryAfterElapsed=SystemClock.elapsedRealtime()+LOAD_RETRY_MS", host)
        self.assertIn("ad_load_failed_code_", host)
        self.assertIn("requestLoadWhenReady()", host)
        self.assertIn("SPDECODE_ADS", host)
        self.assertIn("!consentInformation.canRequestAds()", host)
        self.assertIn("!success||partial", host)
        self.assertIn("onContinue={}", host)
        self.assertNotIn("count>=3", host)
        self.assertNotIn("putString(", host) # No decoded payloads stored in ad telemetry.

    def test_every_file_ads_qa_excludes_catalogs_and_keeps_production_caps(self):
        gradle = read("android/app/build.gradle.kts")
        activity = read("android/app/src/main/java/com/ghostdeveloper/spdecode/MainActivity.kt")
        host = read("android/app/src/unityAds/java/com/ghostdeveloper/spdecode/ads/UnityInterstitialHost.kt")
        self.assertIn('spdecodeAdsEveryFileQa', gradle)
        self.assertIn('SPDECODE_ADS_EVERY_FILE_QA', gradle)
        self.assertIn('(!previewDeferred || BuildConfig.SPDECODE_ADS_EVERY_FILE_QA)', gradle)
        self.assertEqual(activity.count("&& !BuildConfig.SPDECODE_ADS_EVERY_FILE_QA"), 2)
        self.assertEqual(activity.count("onlineAds?.onSavedResult("), 5)
        self.assertIn("val qaEveryFile=BuildConfig.SPDECODE_ADS_EVERY_FILE_QA", host)
        self.assertIn("val blockedByPacing=!qaEveryFile", host)
        self.assertIn("val blockedByDailyCap=!qaEveryFile", host)
        self.assertIn("showQaFeedback(activity,feedback)", host)
        self.assertIn("LevelPlay no inicializado", host)
        self.assertIn("UMP no permite anuncios", host)
        self.assertIn("success=(saved||qaEveryFile)", host)
        self.assertNotIn('putString(', host)

    def test_decoded_catalogs_render_on_home_and_request_ads(self):
        gradle = read("android/app/build.gradle.kts")
        activity = read("android/app/src/main/java/com/ghostdeveloper/spdecode/MainActivity.kt")
        viewer = read("android/app/src/main/java/com/ghostdeveloper/spdecode/LargeResultViewer.kt")
        self.assertIn('val catalog=entry.extension=="nurservers" || entry.extension=="vpnservers"', gradle)
        self.assertIn("if(catalog) {", gradle)
        self.assertIn("showLargeResultWarning=false", gradle)
        self.assertIn("result=entry", gradle)
        self.assertIn("return false", gradle)
        self.assertIn('entry.rawText.length>=250_000', gradle)
        self.assertIn('updateResultBlock("    private fun decodeNurServers() {"', gradle)
        self.assertIn('updateResultBlock("    private fun decodeServerVpnProvider(id:String) {"', gradle)
        self.assertIn('val previewDeferred=presentDecodedRecord(', gradle)
        self.assertIn('tab=if(previewDeferred)1 else 0', gradle)
        for start,end in (
            ("    private fun decodeNurServers() {","    private fun clearVisibleResult() {"),
            ("    private fun decodeServerVpnProvider(id:String) {","    private fun importFiles(uris:List<Uri>,"),
        ):
            part = activity.split(start,1)[1].split(end,1)[0]
            self.assertIn("onlineAds?.onSavedResult(this@MainActivity,record.id,saved)", part)
            self.assertIn("if(BuildConfig.SPDECODE_UNITY_ADS_ENABLED)", part)
            self.assertNotIn("&& !BuildConfig.SPDECODE_ADS_EVERY_FILE_QA", part)
        self.assertIn("NativeResultEngine.open(source)", viewer)
        self.assertIn("ContinuousJsonView", viewer)

    def test_qa_defers_until_window_focus_returns(self):
        interface = read("android/app/src/main/java/com/ghostdeveloper/spdecode/OnlineAds.kt")
        activity = read("android/app/src/main/java/com/ghostdeveloper/spdecode/MainActivity.kt")
        host = read("android/app/src/unityAds/java/com/ghostdeveloper/spdecode/ads/UnityInterstitialHost.kt")
        self.assertIn("fun onWindowFocusChanged(activity:Activity,hasFocus:Boolean)", interface)
        self.assertIn("override fun onWindowFocusChanged(hasFocus:Boolean)", activity)
        self.assertIn("onlineAds?.onWindowFocusChanged(this,hasFocus)", activity)
        self.assertIn('Log.i(LOG_TAG,"ad_deferred_$reason")', host)
        self.assertIn("deferAd(activity,operationId,success,\"window_focus\")", host)
        self.assertIn("activity.window.decorView.postDelayed({flushDeferred(activity)},150L)", host)
        self.assertIn("DEFERRED_AD_TTL_MS=30_000L", host)
        self.assertIn("if(!activity.hasWindowFocus())return", host)
        self.assertIn("ad_deferred_ready", host)
        self.assertIn("clearDeferred()", host)
        self.assertIn("consentInformation.canRequestAds()", host)
        self.assertNotIn("putString(", host)

    def test_ad_load_cooldown_and_silent_release_telemetry(self):
        host = read("android/app/src/unityAds/java/com/ghostdeveloper/spdecode/ads/UnityInterstitialHost.kt")
        self.assertIn("LOAD_COOLDOWN_MS=60_000L", host)
        self.assertIn("lastLoadRequestedElapsed=now", host)
        self.assertIn("now-lastLoadRequestedElapsed<LOAD_COOLDOWN_MS", host)
        self.assertIn("now<retryAfterElapsed", host)
        self.assertIn("if(BuildConfig.DEBUG) Toast.makeText(", host)
        self.assertIn("MAX_DAILY_ADS=12", host)
        self.assertIn("MIN_INTERVAL_MS=240_000L", host)
        self.assertIn("val qaEveryFile=BuildConfig.SPDECODE_ADS_EVERY_FILE_QA", host)

    def test_native_commerce_navigation_and_api_ip_gate(self):
        drawer = read("android/app/src/main/java/com/ghostdeveloper/spdecode/AccountDrawer.kt")
        ui = read("android/app/src/main/java/com/ghostdeveloper/spdecode/NativeCommerceScreens.kt")
        activity = read("android/app/src/main/java/com/ghostdeveloper/spdecode/MainActivity.kt")
        self.assertIn('navigate("account")', drawer)
        self.assertIn('navigate("store")', drawer)
        self.assertIn('navigate("login")', drawer)
        self.assertIn('NativeCommerceScreens(start=route', drawer)
        self.assertNotIn('https://spdecode.xyz/account', drawer)
        self.assertNotIn('https://spdecode.xyz/store', drawer)
        self.assertNotIn('R.string.apk_analysis_coming_soon', drawer)
        self.assertNotIn('"https://spdecode.xyz/account"', activity)
        self.assertNotIn('"https://spdecode.xyz/store"', activity)
        self.assertIn('internal object CommercialServerIp', ui)
        self.assertIn('CommercialServerIp.isPublicLiteral(serverIp)', ui)
        self.assertIn('serverIp.isBlank()||CommercialServerIp.isPublicLiteral(serverIp)', ui)
        self.assertIn('placeholder={Text("195.233.233.12")}', ui)
        self.assertNotIn('placeholder={Text("8.8.8.8")}', ui)
        market=read("android/app/src/main/java/com/ghostdeveloper/spdecode/NativeStoreCatalog.kt")
        self.assertIn('https://spdecode.xyz/api/store/catalog',market)
        self.assertIn('optJSONObject("prices")?.optInt("USD",0)',market)
        self.assertNotIn('CreditPack(1,399)', ui)
        self.assertNotIn('ApiTerm("1m",30,599)', ui)
        for text in ('Descifrado de archivos','Descifrado de textos','Métodos online',
                     'Descifrado de catálogos','No incluye análisis de aplicaciones APK/APKS'):
            self.assertIn(text,ui)
        self.assertIn('enabled=false', ui) # No active payment or password checkout.
        self.assertIn('NativeCommerceScreens(start:String,onExit:()->Unit)',ui)
        self.assertNotIn('android.webkit.WebView',ui)

    def test_all_commerce_locales_and_native_google_auth(self):
        native = read("android/app/src/main/java/com/ghostdeveloper/spdecode/NativeCommerceScreens.kt")
        i18n = read("android/app/src/main/java/com/ghostdeveloper/spdecode/CommerceI18n.kt")
        langs = read("android/app/src/main/java/com/ghostdeveloper/spdecode/CommerceLanguageData.kt")
        auth = read("android/app/src/main/java/com/ghostdeveloper/spdecode/NativeCommerceAuth.kt")
        self.assertIn("context.resources.configuration.locales[0].language",native)
        self.assertIn("CommerceI18n.translate(language,es,en)",native)
        self.assertIn("GoogleIdTokenCredential.createFrom",auth)
        self.assertIn("AndroidKeyStore",auth)
        self.assertIn('"/api/auth/sign-in/social"',auth)
        self.assertIn('"/api/account/api-ip"',auth)
        self.assertIn("optJSONObject(\"user\")",native)
        for locale in ("pt","fr","de","it","ru","tr","ar","fa","hi","ja","id","vi"):
            self.assertIn('"' + locale + '" to """',langs)
        self.assertIn("internal val keys=listOf(",i18n)
        self.assertIn('val creditPacks=catalog?.creditPacks.orEmpty()',native)
        self.assertIn('enabled=apiSelection?.available==true',native)

    def test_commerce_catalog_ip_and_translation_alignment(self):
        import re
        ui=read("android/app/src/main/java/com/ghostdeveloper/spdecode/NativeCommerceScreens.kt")
        keys=read("android/app/src/main/java/com/ghostdeveloper/spdecode/CommerceI18n.kt")
        translations=read("android/app/src/main/java/com/ghostdeveloper/spdecode/CommerceLanguageData.kt")
        product=read("cloud/web/lib/commerce/catalog.mjs")
        orders=read("cloud/web/lib/commerce/orders.mjs")
        api=read("cloud/web/lib/commerce/api.mjs")
        self.assertIn('priceCents<unit*item.credits',ui)
        self.assertIn('optJSONObject("prices")?.optInt("USD",0)',read(
            "android/app/src/main/java/com/ghostdeveloper/spdecode/NativeStoreCatalog.kt"))
        self.assertIn("body.allowedIp!==undefined",product)
        self.assertIn("if(item.product_id==='api-ip'&&!publicIp(item.allowed_ip))",orders)
        self.assertIn("export async function updateApiAllowedIp",orders)
        self.assertIn("export const apiIpMutation",api)
        self.assertIn("apiIpMutation",read("cloud/web/app/api/account/api-ip/route.js"))
        count=len(re.findall(r'^\s*"[^"]+",?
        viewer = read("android/app/src/main/java/com/ghostdeveloper/spdecode/LargeResultViewer.kt")
        self.assertIn("current.lineCount.coerceIn(1, 150)", viewer)
        self.assertIn("visibleLines * 19f * fontScale + 16f", viewer)
        self.assertIn(".height(jsonHeightDp.dp)", viewer)
        self.assertNotIn("current.lineCount.coerceIn(4, 150) * 22f", viewer)
        self.assertIn("NativeResultEngine.open(source)", viewer)
        self.assertIn("ContinuousJsonView", viewer)

    def test_apk_credits_button_removed_in_favor_of_store(self):
        app = read("android/app/src/main/java/com/ghostdeveloper/spdecode/SpDecodeApp.kt")
        drawer = read("android/app/src/main/java/com/ghostdeveloper/spdecode/AccountDrawer.kt")
        self.assertNotIn("creditsPage", app)
        self.assertNotIn("apk_credits_open", app)
        self.assertNotIn("showCreditsAction", app)
        self.assertIn("2->if(BuildConfig.SPDECODE_APK_QA_ENABLED)", app)
        self.assertIn("showServerVpnRefresh=(activeTab==3 || activeTab==2)", app)
        self.assertIn('navigate("store")', drawer)

    def test_json_selection_can_be_cancelled_without_copying(self):
        viewer = read("android/app/src/main/java/com/ghostdeveloper/spdecode/ContinuousJsonView.kt")
        self.assertIn("MENU_CANCEL_SELECTION", viewer)
        self.assertIn("context.getString(R.string.cancel)", viewer)
        self.assertIn("mode.finish()", viewer)
        self.assertIn("private fun dismissSelection()", viewer)
        self.assertIn("if(selectionStart!=null || selectionEnd!=null)", viewer)
        self.assertIn("dismissSelection()", viewer)
        self.assertIn("contextMode?.finish()", viewer)

    def test_android_recents_use_single_application_task(self):
        host = read("android/app/src/unityAds/java/com/ghostdeveloper/spdecode/ads/UnityInterstitialHost.kt")
        for manifest_path in (
            "android/app/src/main/AndroidManifest.xml",
            "android/app/src/cloud/AndroidManifest.xml",
        ):
            manifest = read(manifest_path)
            self.assertIn('android:documentLaunchMode="never"', manifest)
            self.assertNotIn('android:documentLaunchMode="intoExisting"', manifest)
        self.assertIn("ad?.showAd(activity)", host)

    def test_legacy_http_custom_json_preview_is_recoverable_without_redecrypting(self):
        viewer = read("android/app/src/main/java/com/ghostdeveloper/spdecode/LargeResultViewer.kt")
        fixture = read("android/app/src/sharedAndroidTest/java/com/ghostdeveloper/spdecode/LargeResultEngineInstrumentedTest.kt")
        self.assertIn("internal fun openJsonResultForViewer", viewer)
        self.assertIn("NativeResultEngine.open(source)", viewer)
        self.assertIn("catch(error:java.io.IOException)", viewer)
        self.assertIn("ResultJsonDisplay.render(raw,suffix)", viewer)
        self.assertIn("if(normalized==source)throw error", viewer)
        self.assertIn("owned = openJsonResultForViewer(raw, suffix)", viewer)
        self.assertIn("legacyHttpCustomPresentationRecoversMalformedJsonAndKeepsDecodedFields", fixture)
        self.assertIn("legacyHttpCustomValidJsonKeepsItsExactBytes", fixture)
        self.assertNotIn("decodeFile(", viewer)

    def test_telegram_decrypt_credits_and_v2ray_export(self):
        def src(name):
            return read("android/app/src/main/java/com/ghostdeveloper/spdecode/"+name)
        self.assertIn('fun normalizeUsername(input:String):String?',src("TelegramResultCopy.kt"))
        self.assertNotIn('Credits: Ghost Developer',src("TelegramResultCopy.kt"))
        self.assertIn('"telegram_decrypt_credit"',src("MainActivity.kt"))
        self.assertIn('decrypt_credits_by',src("MainActivity.kt"))
        self.assertIn('telegram_decrypt_credit',src("FunctionalSettingsPanel.kt"))
        self.assertIn('onCopyV2rayLinks(links.joinToString',src("SpDecodeApp.kt"))
        self.assertIn('V2rayShareLinks.extract(current.rawText)',src("SpDecodeApp.kt"))
        self.assertIn('if(nestedV2ray || !startsAsJson)',src("LargeResultViewer.kt"))
        link_parser=src("V2rayShareLinks.kt")
        for protocol in ("vmess","vless","trojan"):
            self.assertIn('"'+protocol+'"',link_parser)
        self.assertIn('if(protocol=="trojan" && security!="tls")return null',link_parser)
        for lang in ("values","values-es","values-pt-rBR","values-fr","values-de",
                     "values-it","values-tr","values-ru","values-ar","values-fa",
                     "values-hi","values-ja","values-in","values-vi"):
            bundle=read("android/app/src/main/res/"+lang+"/strings.xml")
            for key in ("decrypt_credits_title","decrypt_credits_by","v2ray_share_auto",
                        "v2ray_share_protocol"):
                self.assertIn('name="'+key+'"',bundle)
        instrumented=read("android/app/src/sharedAndroidTest/java/com/ghostdeveloper/spdecode/V2rayShareLinksInstrumentedTest.kt")
        self.assertIn("vmessLinkRetainsCompleteWebsocketTlsFields",instrumented)
        self.assertIn("onlyRealProtocolOutboundsProduceLinks",instrumented)
        self.assertIn("telegramCreditsAreNormalizedAndNotDuplicated",instrumented)

    def test_saved_telegram_decryption_credit_can_be_edited_and_removed(self):
        ui = read("android/app/src/main/java/com/ghostdeveloper/spdecode/FunctionalSettingsPanel.kt")
        main = read("android/app/src/main/java/com/ghostdeveloper/spdecode/MainActivity.kt")
        app = read("android/app/src/main/java/com/ghostdeveloper/spdecode/SpDecodeApp.kt")
        self.assertIn("if(hasSavedCredit && !editingCredit)", ui)
        self.assertIn('testTag("telegram_decrypt_credit_saved")', ui)
        self.assertIn('testTag("telegram_decrypt_credit_edit")', ui)
        self.assertIn('testTag("telegram_decrypt_credit_delete")', ui)
        self.assertIn('if(onSaveTelegramCredit(""))', ui)
        self.assertIn("if(editor.commit()){", main)
        self.assertIn('editor.remove("telegram_decrypt_credit")', main)
        self.assertIn("telegramCreditUsername=normalized", main)
        self.assertIn("onSaveTelegramCredit:(String)->Boolean", ui)
        self.assertIn("onSaveTelegramCredit:(String)->Boolean", app)
        self.assertIn("telegramCreditUsername.takeIf{it.isNotBlank()}", main)
        all_locales=("values","values-es","values-pt-rBR","values-fr","values-de",
                     "values-it","values-tr","values-ru","values-ar","values-fa",
                     "values-hi","values-ja","values-in","values-vi")
        for locale in all_locales:
            strings = read(f"android/app/src/main/res/{locale}/strings.xml")
            for resource in ("decrypt_credits_edit","decrypt_credits_delete",
                             "decrypt_credits_delete_confirm"):
                self.assertIn(f'name="{resource}"', strings)

    def test_vps_online_fails_closed_for_missing_ads(self):
        build = read("cloud/infra/vps/android-public-build.sh")
        self.assertIn('UNITY_CONFIG="$CFG/unity-ads.env"', build)
        self.assertIn("Incomplete Unity/CMP identifiers", build)
        self.assertIn('UNITY_ARGS+=("-PspdecodeUnityAds=true")', build)

    def test_commercial_v1_independent_of_legacy_v1(self):
        route = read("cloud/web/app/api/commercial/v1/decode/route.js")
        backend = read("cloud/web/lib/commerce/api.mjs")
        legacy = read("cloud/web/lib/v1-gate.mjs")
        self.assertIn("POST=commercialDecode", route)
        self.assertIn("SPDECODE_COMMERCIAL_API_ENABLED", backend)
        self.assertIn("checkApiKey", backend)
        self.assertIn("useApiKey", backend)
        self.assertIn("V1_API_DISABLED", legacy)


if __name__ == "__main__":
    unittest.main()
,keys,re.MULTILINE))
        translationsFound=dict(re.findall(r'"(pt|fr|de|it|ru|tr|ar|fa|hi|ja|id|vi)" to """\n(.*?)\n""".trimIndent\(\).lines\(\)',translations,re.DOTALL))
        self.assertEqual(12,len(translationsFound))
        for locale,entry in translationsFound.items():
            self.assertEqual(109,len(entry.splitlines()),locale)
        self.assertGreaterEqual(count,109)

    def test_json_height_tracks_native_lines_for_short_results(self):
        viewer = read("android/app/src/main/java/com/ghostdeveloper/spdecode/LargeResultViewer.kt")
        self.assertIn("current.lineCount.coerceIn(1, 150)", viewer)
        self.assertIn("visibleLines * 19f * fontScale + 16f", viewer)
        self.assertIn(".height(jsonHeightDp.dp)", viewer)
        self.assertNotIn("current.lineCount.coerceIn(4, 150) * 22f", viewer)
        self.assertIn("NativeResultEngine.open(source)", viewer)
        self.assertIn("ContinuousJsonView", viewer)

    def test_apk_credits_button_removed_in_favor_of_store(self):
        app = read("android/app/src/main/java/com/ghostdeveloper/spdecode/SpDecodeApp.kt")
        drawer = read("android/app/src/main/java/com/ghostdeveloper/spdecode/AccountDrawer.kt")
        self.assertNotIn("creditsPage", app)
        self.assertNotIn("apk_credits_open", app)
        self.assertNotIn("showCreditsAction", app)
        self.assertIn("2->if(BuildConfig.SPDECODE_APK_QA_ENABLED)", app)
        self.assertIn("showServerVpnRefresh=(activeTab==3 || activeTab==2)", app)
        self.assertIn('navigate("store")', drawer)

    def test_json_selection_can_be_cancelled_without_copying(self):
        viewer = read("android/app/src/main/java/com/ghostdeveloper/spdecode/ContinuousJsonView.kt")
        self.assertIn("MENU_CANCEL_SELECTION", viewer)
        self.assertIn("context.getString(R.string.cancel)", viewer)
        self.assertIn("mode.finish()", viewer)
        self.assertIn("private fun dismissSelection()", viewer)
        self.assertIn("if(selectionStart!=null || selectionEnd!=null)", viewer)
        self.assertIn("dismissSelection()", viewer)
        self.assertIn("contextMode?.finish()", viewer)

    def test_android_recents_use_single_application_task(self):
        host = read("android/app/src/unityAds/java/com/ghostdeveloper/spdecode/ads/UnityInterstitialHost.kt")
        for manifest_path in (
            "android/app/src/main/AndroidManifest.xml",
            "android/app/src/cloud/AndroidManifest.xml",
        ):
            manifest = read(manifest_path)
            self.assertIn('android:documentLaunchMode="never"', manifest)
            self.assertNotIn('android:documentLaunchMode="intoExisting"', manifest)
        self.assertIn("ad?.showAd(activity)", host)

    def test_legacy_http_custom_json_preview_is_recoverable_without_redecrypting(self):
        viewer = read("android/app/src/main/java/com/ghostdeveloper/spdecode/LargeResultViewer.kt")
        fixture = read("android/app/src/sharedAndroidTest/java/com/ghostdeveloper/spdecode/LargeResultEngineInstrumentedTest.kt")
        self.assertIn("internal fun openJsonResultForViewer", viewer)
        self.assertIn("NativeResultEngine.open(source)", viewer)
        self.assertIn("catch(error:java.io.IOException)", viewer)
        self.assertIn("ResultJsonDisplay.render(raw,suffix)", viewer)
        self.assertIn("if(normalized==source)throw error", viewer)
        self.assertIn("owned = openJsonResultForViewer(raw, suffix)", viewer)
        self.assertIn("legacyHttpCustomPresentationRecoversMalformedJsonAndKeepsDecodedFields", fixture)
        self.assertIn("legacyHttpCustomValidJsonKeepsItsExactBytes", fixture)
        self.assertNotIn("decodeFile(", viewer)

    def test_telegram_decrypt_credits_and_v2ray_export(self):
        def src(name):
            return read("android/app/src/main/java/com/ghostdeveloper/spdecode/"+name)
        self.assertIn('fun normalizeUsername(input:String):String?',src("TelegramResultCopy.kt"))
        self.assertNotIn('Credits: Ghost Developer',src("TelegramResultCopy.kt"))
        self.assertIn('"telegram_decrypt_credit"',src("MainActivity.kt"))
        self.assertIn('decrypt_credits_by',src("MainActivity.kt"))
        self.assertIn('telegram_decrypt_credit',src("FunctionalSettingsPanel.kt"))
        self.assertIn('onCopyV2rayLinks(links.joinToString',src("SpDecodeApp.kt"))
        self.assertIn('V2rayShareLinks.extract(current.rawText)',src("SpDecodeApp.kt"))
        self.assertIn('if(nestedV2ray || !startsAsJson)',src("LargeResultViewer.kt"))
        link_parser=src("V2rayShareLinks.kt")
        for protocol in ("vmess","vless","trojan"):
            self.assertIn('"'+protocol+'"',link_parser)
        self.assertIn('if(protocol=="trojan" && security!="tls")return null',link_parser)
        for lang in ("values","values-es","values-pt-rBR","values-fr","values-de",
                     "values-it","values-tr","values-ru","values-ar","values-fa",
                     "values-hi","values-ja","values-in","values-vi"):
            bundle=read("android/app/src/main/res/"+lang+"/strings.xml")
            for key in ("decrypt_credits_title","decrypt_credits_by","v2ray_share_auto",
                        "v2ray_share_protocol"):
                self.assertIn('name="'+key+'"',bundle)
        instrumented=read("android/app/src/sharedAndroidTest/java/com/ghostdeveloper/spdecode/V2rayShareLinksInstrumentedTest.kt")
        self.assertIn("vmessLinkRetainsCompleteWebsocketTlsFields",instrumented)
        self.assertIn("onlyRealProtocolOutboundsProduceLinks",instrumented)
        self.assertIn("telegramCreditsAreNormalizedAndNotDuplicated",instrumented)

    def test_saved_telegram_decryption_credit_can_be_edited_and_removed(self):
        ui = read("android/app/src/main/java/com/ghostdeveloper/spdecode/FunctionalSettingsPanel.kt")
        main = read("android/app/src/main/java/com/ghostdeveloper/spdecode/MainActivity.kt")
        app = read("android/app/src/main/java/com/ghostdeveloper/spdecode/SpDecodeApp.kt")
        self.assertIn("if(hasSavedCredit && !editingCredit)", ui)
        self.assertIn('testTag("telegram_decrypt_credit_saved")', ui)
        self.assertIn('testTag("telegram_decrypt_credit_edit")', ui)
        self.assertIn('testTag("telegram_decrypt_credit_delete")', ui)
        self.assertIn('if(onSaveTelegramCredit(""))', ui)
        self.assertIn("if(editor.commit()){", main)
        self.assertIn('editor.remove("telegram_decrypt_credit")', main)
        self.assertIn("telegramCreditUsername=normalized", main)
        self.assertIn("onSaveTelegramCredit:(String)->Boolean", ui)
        self.assertIn("onSaveTelegramCredit:(String)->Boolean", app)
        self.assertIn("telegramCreditUsername.takeIf{it.isNotBlank()}", main)
        all_locales=("values","values-es","values-pt-rBR","values-fr","values-de",
                     "values-it","values-tr","values-ru","values-ar","values-fa",
                     "values-hi","values-ja","values-in","values-vi")
        for locale in all_locales:
            strings = read(f"android/app/src/main/res/{locale}/strings.xml")
            for resource in ("decrypt_credits_edit","decrypt_credits_delete",
                             "decrypt_credits_delete_confirm"):
                self.assertIn(f'name="{resource}"', strings)

    def test_vps_online_fails_closed_for_missing_ads(self):
        build = read("cloud/infra/vps/android-public-build.sh")
        self.assertIn('UNITY_CONFIG="$CFG/unity-ads.env"', build)
        self.assertIn("Incomplete Unity/CMP identifiers", build)
        self.assertIn('UNITY_ARGS+=("-PspdecodeUnityAds=true")', build)

    def test_commercial_v1_independent_of_legacy_v1(self):
        route = read("cloud/web/app/api/commercial/v1/decode/route.js")
        backend = read("cloud/web/lib/commerce/api.mjs")
        legacy = read("cloud/web/lib/v1-gate.mjs")
        self.assertIn("POST=commercialDecode", route)
        self.assertIn("SPDECODE_COMMERCIAL_API_ENABLED", backend)
        self.assertIn("checkApiKey", backend)
        self.assertIn("useApiKey", backend)
        self.assertIn("V1_API_DISABLED", legacy)


if __name__ == "__main__":
    unittest.main()
