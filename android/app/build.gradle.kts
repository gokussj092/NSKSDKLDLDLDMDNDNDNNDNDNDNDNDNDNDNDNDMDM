import java.io.File
import java.net.URI
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("org.jetbrains.kotlin.plugin.compose")
    id("org.jetbrains.kotlin.kapt")
}

// Phase S: isolate source-controlled decoder material from packaged assets.
// A random build-local AES-GCM wrapper prevents plaintext JSON extraction by
// unzipping the APK. Its runtime key is compiled into the APK and is recoverable
// by reverse engineering: this is hardening, NOT absolute confidentiality.
val vaultNames = setOf(
    "embedded_kotlin_profiles.json",
    "flex_f_profiles.json",
    "generic_b_profiles.json",
    "hc_source_keys.json",
    "http_tweak_source_tables.json",
    "legacy_epro_npv2_keys.json",
    "npvs_v5_tables.b85",
    "nur_tunnel_server_endpoint.json",
    "npv_whitebox.bin", // generated before Gradle when available
    "renz_d_profiles.json",
    "ultra_c_profiles.json",
)
val vaultOriginalAssets = layout.projectDirectory.dir("src/main/assets")
val vaultPackagedAssets = layout.buildDirectory.dir("generated/spdecode-vault/assets")
val vaultGeneratedKotlin = layout.buildDirectory.dir("generated/spdecode-vault/kotlin")
val prepareSecureAssetVault = tasks.register("prepareSecureAssetVault") {
    inputs.dir(vaultOriginalAssets)
    outputs.dir(vaultPackagedAssets)
    outputs.dir(vaultGeneratedKotlin)
    doLast {
        val source = vaultOriginalAssets.asFile
        val destination = vaultPackagedAssets.get().asFile
        val codeRoot = vaultGeneratedKotlin.get().asFile
        require(source.isDirectory) { "Decoder asset sources missing" }
        destination.deleteRecursively()
        codeRoot.deleteRecursively()
        destination.mkdirs()
        val random = SecureRandom()
        val key = ByteArray(32).also(random::nextBytes)
        val share = ByteArray(32).also(random::nextBytes)
        val other = ByteArray(32) { i -> (key[i].toInt() xor share[i].toInt()).toByte() }
        try {
            source.walkTopDown().filter { it.isFile }.forEach { input ->
                val relative = input.relativeTo(source).invariantSeparatorsPath
                val isProtected = relative in vaultNames
                val output = File(destination, if (isProtected) "$relative.spv" else relative)
                output.parentFile.mkdirs()
                if (!isProtected) {
                    input.copyTo(output, overwrite = true)
                } else {
                    val nonce = ByteArray(12).also(random::nextBytes)
                    val cipher = Cipher.getInstance("AES/GCM/NoPadding")
                    cipher.init(
                        Cipher.ENCRYPT_MODE,
                        SecretKeySpec(key, "AES"),
                        GCMParameterSpec(128, nonce),
                    )
                    cipher.updateAAD("spdecode:s1:$relative".toByteArray(Charsets.UTF_8))
                    output.writeBytes(
                        "SPV1".toByteArray(Charsets.US_ASCII) +
                            nonce + cipher.doFinal(input.readBytes())
                    )
                }
            }
            val required = vaultNames - "npv_whitebox.bin"
            require(required.all { File(destination, "$it.spv").isFile }) {
                "Missing secure vault source material"
            }
            require(vaultNames.none { File(destination, it).exists() }) {
                "Plaintext protected asset was packaged"
            }
            val keyFile = File(
                codeRoot,
                "com/ghostdeveloper/spdecode/parity/VaultBuildKey.kt",
            )
            keyFile.parentFile.mkdirs()
            val first = share.joinToString(",") { (it.toInt() and 255).toString() }
            val second = other.joinToString(",") { (it.toInt() and 255).toString() }
            keyFile.writeText(
                """package com.ghostdeveloper.spdecode.parity

internal object VaultBuildKey {
    // Generated per build; these bytes are still extractable from the APK.
    internal fun material(): ByteArray {
        val a = intArrayOf($first)
        val b = intArrayOf($second)
        return ByteArray(32) { i -> (a[i] xor b[i]).toByte() }
    }
}
""",
                Charsets.UTF_8,
            )
        } finally {
            key.fill(0)
            share.fill(0)
            other.fill(0)
        }
    }
}

val cloudOrigin=providers.environmentVariable("SPDECODE_CLOUD_API_BASE_URL").orNull.orEmpty().trim()
val enableCloud=cloudOrigin.isNotEmpty()
val enableQaBuild=providers.environmentVariable("SPDECODE_CLOUD_QA_BUILD").orNull=="true"
// Play In-App Updates is an AAB-only compile-time feature, not a runtime switch.
// Ordinary signed APKs (Telegram), legacy/QA builds and ownership proofs omit it.
val enablePlayAab=providers.gradleProperty("spdecodePlayAab").orNull=="true"
require(!enablePlayAab || (enableCloud && !enableQaBuild)) {
    "Play update AAB requires a non-QA Cloud build"
}
require(!enableQaBuild || enableCloud) { "QA mode requires Cloud API" }
if(enableCloud) {
    val parsed=URI(cloudOrigin)
    require(parsed.scheme=="https" &&
        parsed.rawUserInfo==null && parsed.port==-1 &&
        parsed.rawQuery==null && parsed.rawFragment==null &&
        parsed.path.orEmpty().isEmpty() &&
        parsed.host!=null && parsed.host.contains(".") &&
        parsed.host.all { it.isLetterOrDigit() || it=='.' || it=='-' } &&
        !parsed.host.matches(Regex("[0-9.]+")) &&
        !parsed.host.endsWith(".local",ignoreCase=true)) {
        "SPDECODE_CLOUD_API_BASE_URL must be an HTTPS domain origin, without paths or credentials"
    }
    require(cloudOrigin == "https://" + parsed.host) {
        "Use the normalized exact Cloud HTTPS origin only"
    }
}
if(providers.environmentVariable("SPDECODE_CLOUD_RELEASE").orNull=="true") {
    require(enableCloud) { "Production Cloud requires SPDECODE_CLOUD_API_BASE_URL" }
}
// Distribution must never accidentally package historical local engines.
gradle.taskGraph.whenReady {
    val distributesRelease=allTasks.any { it.project==project &&
        it.name in setOf("assembleRelease","packageRelease","bundleRelease") }
    val hasPlayBundle=allTasks.any { it.project==project && it.name=="bundleRelease" }
    if(hasPlayBundle) require(enablePlayAab) {
        "Every release AAB must enable -PspdecodePlayAab=true and be built separately"
    }
    if(enablePlayAab) {
        require(hasPlayBundle &&
            allTasks.none { it.project==project &&
                it.name in setOf("assembleRelease","packageRelease") }) {
            "Play AAB must be built separately: -PspdecodePlayAab=true :app:bundleRelease"
        }
    }
    if(distributesRelease) {
        require(enableCloud) { "Release distribution requires the Cloud-only source set" }
        require(!enableQaBuild) { "Release distribution must not enable the legacy QA launcher" }
    }
}
// C5 Cloud build compiles a STRICT allowlisted copy of client-only sources.
// Original decoders remain in git for legacy regression and the server, but
// are not a Kotlin/Java input and cannot be recovered from a Cloud APK.
val cloudSourceRoot = layout.buildDirectory.dir("generated/c5-client/java")
val cloudAssetRoot = layout.buildDirectory.dir("generated/c5-client/assets")
// Preserve the nine frozen C0 UI files. QA builds patch only a generated
// copy of Settings; release builds never compile this generated variant.
val qaSettingsRelativePath = "com/ghostdeveloper/spdecode/FunctionalSettingsPanel.kt"
val qaSettingsSource = layout.projectDirectory.file("src/main/java/$qaSettingsRelativePath")
val qaSettingsRoot = layout.buildDirectory.dir("generated/c5-qa-settings/java")
val prepareQaSettingsSource = tasks.register("prepareQaSettingsSource") {
    inputs.file(qaSettingsSource)
    outputs.dir(qaSettingsRoot)
    doLast {
        val original = qaSettingsSource.asFile.readText(Charsets.UTF_8)
        val anchor = "        // Settings additions injected here by the Android Gradle task."
        require(original.indexOf(anchor) >= 0 &&
            original.indexOf(anchor) == original.lastIndexOf(anchor)) {
            "QA Settings injection anchor absent or ambiguous; do not ship a build"
        }
        val source = original.replace(anchor,
            (if(enableQaBuild) "        com.ghostdeveloper.spdecode.cloud.CloudQaSettingsCard()\n" else "") +
            "        com.ghostdeveloper.spdecode.cloud.DonationSettingsCard()\n" +
            "        com.ghostdeveloper.spdecode.cloud.NpvsIdentitySettings()\n" +
            "        com.ghostdeveloper.spdecode.cloud.PrivateScreenSettings()\n" + anchor)
        val output = qaSettingsRoot.get().file(qaSettingsRelativePath).asFile
        output.parentFile.mkdirs()
        output.writeText(source, Charsets.UTF_8)
    }
}
// C0 UI sources remain byte-for-byte unchanged; only Cloud builds receive
// generated copies with the minimal safe-preview/history-export behavior.
val cloudHistoryUiRoot = layout.buildDirectory.dir("generated/cloud-history-ui/java")
val prepareCloudHistoryUiSource = tasks.register("prepareCloudHistoryUiSource") {
    val originalRoot = layout.projectDirectory.dir("src/main/java/com/ghostdeveloper/spdecode")
    inputs.files(originalRoot.file("SpDecodeApp.kt"), originalRoot.file("MainActivity.kt"))
    inputs.property("spdecodePlayAab",enablePlayAab)
    outputs.dir(cloudHistoryUiRoot)
    doLast {
        fun replaceOnce(source:String, old:String, replacement:String):String {
            require(source.indexOf(old)>=0 && source.indexOf(old)==source.lastIndexOf(old)) {
                "Cloud history UI anchor absent or ambiguous: " + old.take(75)
            }
            return source.replace(old,replacement)
        }
        val appPath = "com/ghostdeveloper/spdecode/SpDecodeApp.kt"
        val activityPath = "com/ghostdeveloper/spdecode/MainActivity.kt"
        var app = originalRoot.file("SpDecodeApp.kt").asFile.readText(Charsets.UTF_8)
        // C0 now already passes cloudFormats and cloudTextFormats to FormatsScreen.
        // The frozen source must not be patched a second time with the old
        // FormatsScreen() / fileFormats signatures. Keep only Cloud-only
        // notices, history actions and preview protections below.
        app = replaceOnce(app,
            "(formats + listOfNotNull(AndroidDecoderCatalog.detect(\"preview.solid\",formats)))",
            "(formats + if(BuildConfig.SPDECODE_CLOUD_ENABLED && cloudFormats.isNotEmpty())\n" +
            "            emptyList() else listOfNotNull(AndroidDecoderCatalog.detect(\"preview.solid\",formats)))")
        app = replaceOnce(app,
            "Text(stringResource(R.string.catalog_note), fontSize = 13.sp,",
            "Text(stringResource(if(BuildConfig.SPDECODE_CLOUD_ENABLED && cloudFormats.isNotEmpty())\n" +
            "            R.string.formats_remote_catalog_note else R.string.catalog_note), fontSize = 13.sp,")
        app = replaceOnce(app,
            "stringResource(\n                            if (extensions.all { it.isPending })",
            "stringResource(\n                            if(BuildConfig.SPDECODE_CLOUD_ENABLED && cloudFormats.isNotEmpty())\n" +
            "                                R.string.formats_cloud_ready_short\n" +
            "                            else if (extensions.all { it.isPending })")
        app = replaceOnce(app,
            "    onDeleteSelected:(Set<String>)->Unit,\n    onFavorite:",
            "    onDeleteSelected:(Set<String>)->Unit,\n    onExportHistory:(DecodeView)->Unit,\n    onFavorite:")
        app = replaceOnce(app,
            "    whatsNew:Boolean=false,",
            "    largeResultWarning:Boolean=false,\n    onDismissLargeResultWarning:()->Unit={},\n    whatsNew:Boolean=false,")
        app = replaceOnce(app,
            "1->HistoryScreen(session,onSelect,onDeleteSelected,onClear,onImportMultiple,onFavorite)",
            "1->HistoryScreen(session,onSelect,onDeleteSelected,onClear,onImportMultiple,onFavorite,onExportHistory)")
        app = replaceOnce(app,
            "Text(stringResource(R.string.decode_progress_title),",
            "Text(stringResource(if(BuildConfig.SPDECODE_CLOUD_ENABLED && progressStage==1) " +
                "R.string.cloud_decode_progress_title else R.string.decode_progress_title),")
        app = replaceOnce(app,
            "else->R.string.decode_progress_decoding",
            "else->if(BuildConfig.SPDECODE_CLOUD_ENABLED) " +
                "R.string.cloud_decode_progress_message else R.string.decode_progress_decoding")
        app = replaceOnce(app,
            "        if(pendingServerVpnCatalogVersion!=null && !busy) AlertDialog(",
            "        if(BuildConfig.SPDECODE_CLOUD_ENABLED) com.ghostdeveloper.spdecode.cloud.NpvsRecipientPicker.Content()\n" +
                "        if(BuildConfig.SPDECODE_CLOUD_ENABLED) com.ghostdeveloper.spdecode.cloud.HttpCustomCloudPrompt.Content()\n" +
                "        if(pendingServerVpnCatalogVersion!=null && !busy) AlertDialog(")
        app = replaceOnce(app,
            "        if(busy) Dialog(",
            "        if(busy && !com.ghostdeveloper.spdecode.cloud.NpvsRecipientPicker.isShowing && !com.ghostdeveloper.spdecode.cloud.HttpCustomCloudPrompt.isShowing) Dialog(")
        app = replaceOnce(app,
            "        if(error!=null && !busy) AlertDialog(",
            "        if(largeResultWarning && !busy) " +
                "com.ghostdeveloper.spdecode.cloud.CloudLargeResultNotice(onDismissLargeResultWarning)\n" +
                "        if(error!=null && !busy) AlertDialog(")
        app = replaceOnce(app,
            "    onFavorite: (String, Boolean) -> Unit,\n) {",
            "    onFavorite: (String, Boolean) -> Unit,\n" +
                "    onExportHistory: (DecodeView) -> Unit,\n) {")
        app = replaceOnce(app,
            """                            IconButton(onClick={
                                deletingAll=false;deletion=setOf(entry.id)
                            }) {
                                Icon(Icons.Outlined.DeleteOutline,
                                    stringResource(R.string.history_delete_one),tint=Secondary)
                            }""",
            """                            com.ghostdeveloper.spdecode.cloud.CloudHistoryEntryActions(
                                entry=entry,
                                onExport={onExportHistory(entry)},
                                onDelete={deletingAll=false;deletion=setOf(entry.id)},
                            )""")
        // C0 SpDecodeApp is immutable. Informational notices are injected
        // ONLY into the Cloud variant, along with matching MainActivity args.
        app = replaceOnce(app,
            "    onDismissError:()->Unit,",
            "    onDismissError:()->Unit,\n    noticeOnly:Boolean=false,".replace("\n","\n"))
        app = replaceOnce(app,
            "title={Text(stringResource(errorTitle))}",
            "title={Text(stringResource(if(noticeOnly) " +
                "R.string.cloud_failure_notice_title else errorTitle))}")

        app = replaceOnce(app,
            """            dismissButton={TextButton(onClick={
                if(canReportError)onReportError()
                else {
                    onDismissError()
                    onExternalLink("https://t.me/Gh0stDeveloper")
                }
            }) {
                Text(stringResource(if(canReportError)R.string.cloud_report_action
                    else R.string.decode_notice_contact),color=White)
            }},""",
            """            dismissButton={
                if(!noticeOnly) TextButton(onClick={
                    if(canReportError)onReportError()
                    else {
                        onDismissError()
                        onExternalLink("https://t.me/Gh0stDeveloper")
                    }
                }) {
                    Text(stringResource(if(canReportError)R.string.cloud_report_action
                        else R.string.decode_notice_contact),color=White)
                }
            },""")
        var activity = originalRoot.file("MainActivity.kt").asFile.readText(Charsets.UTF_8)
        // Global Cloud panel has two arguments, unlike the single-input legacy
        // panel in the main source set. Adapt only the generated Cloud Activity.
        // Never add an API endpoint, key or server policy to Kotlin.
        activity = replaceOnce(activity,
            """                onDecodeCloud={reference->decodeCloud("auto",reference)},""",
            """                onDecodeCloud={provider,reference->decodeCloud(provider,reference)},""")
        // Only the Cloud artifact uses the verified downloadable text inventory.
        // Preserve C0's legacy fallback without leaking it into Cloud builds.
        activity = replaceOnce(activity,
            """        val candidate=(if(BuildConfig.SPDECODE_CLOUD_ENABLED)
            CloudTextFormats.identify(userText,textRoutes) else null)
            ?:TextProtocolDecoder.identify(userText)""",
            """        val candidate=if(BuildConfig.SPDECODE_CLOUD_ENABLED)
            CloudTextFormats.identify(userText,textRoutes)
            else TextProtocolDecoder.identify(userText)""")
        activity = replaceOnce(activity,
            "                error=message,",
            "                error=message,\n                noticeOnly=messageIsCredentialNotice,")
        // Navigation already uses the in-memory catalog snapshot. Do not add
        // refresh hooks when generating Cloud UI sources.
        // Android 15/16: Cloud builds opt into edge-to-edge on older devices too.
        // The original C0 UI sources stay byte-for-byte unchanged.
        activity = replaceOnce(activity,
            "import androidx.activity.ComponentActivity",
            "import androidx.activity.ComponentActivity\n" +
                "import androidx.activity.SystemBarStyle\n" +
                "import androidx.activity.enableEdgeToEdge")
        activity = replaceOnce(activity,
            """        @Suppress("DEPRECATION")
        window.statusBarColor=android.graphics.Color.BLACK
        @Suppress("DEPRECATION")
        window.navigationBarColor=android.graphics.Color.BLACK
        window.decorView.systemUiVisibility=0""",
            """        // Edge-to-edge is explicit for API 24-34 and enforced for API 35+.
        // SpDecodeApp's safeDrawingPadding() prevents toolbar and tabs overlap.
        enableEdgeToEdge(
            statusBarStyle=SystemBarStyle.dark(android.graphics.Color.TRANSPARENT),
            navigationBarStyle=SystemBarStyle.dark(android.graphics.Color.TRANSPARENT),
        )""")
        activity = replaceOnce(activity,
            "    private var stagedExport:String?=null",
            "    private var stagedExport:String?=null\n" +
                "    private var showLargeResultWarning by mutableStateOf(false)")
        activity = replaceOnce(activity,
            "                onDeleteSelected={ids->deleteHistory(ids)},",
            """                onDeleteSelected={ids->deleteHistory(ids)},
                onExportHistory={entry->export(
                    com.ghostdeveloper.spdecode.cloud.CloudHistoryJsonExport.content(entry),
                    entry.filename,ResultExport.JSON)},
            """.trimEnd())
        activity = replaceOnce(activity,
            "                onDecodeServerCatalog={decodeNurServers()},",
            """                onDecodeServerCatalog={decodeNurServers()},
                largeResultWarning=showLargeResultWarning,
                onDismissLargeResultWarning={showLargeResultWarning=false},""")
        activity = replaceOnce(activity,
            "    private fun decodeText(userText:String,password:ByteArray?=null) {",
            """    // Large JSON documents must never be parsed eagerly by the preview.
    // The complete result is already saved in encrypted history.
    private fun presentDecodedRecord(entry:DecodeView, stored:Boolean):Boolean {
        val large=BuildConfig.SPDECODE_CLOUD_ENABLED && stored &&
            (entry.extension=="nurservers" || entry.extension=="vpnservers" ||
                entry.rawText.length>=250_000)
        if(large) {
            result=null
            reveal=false
            showLargeResultWarning=true
        }else result=entry
        return large
    }

    private fun decodeText(userText:String,password:ByteArray?=null) {""")
        // Dedicated replacements preserve the original flows on all formats.
        fun updateResultBlock(start:String,end:String,entry:String,saved:String):Unit {
            val from=activity.indexOf(start)
            val to=activity.indexOf(end,from+start.length)
            require(from>=0 && to>from) {"Cloud activity decode section unavailable: "+start}
            var section=activity.substring(from,to)
            section=replaceOnce(section,"                result="+entry,
                "                val previewDeferred=presentDecodedRecord("+entry+","+saved+")")
            section=replaceOnce(section,"historyPreferences.setSelectedId("+entry+".id)",
                "historyPreferences.setSelectedId(if(previewDeferred) null else "+entry+".id)")
            section=replaceOnce(section,"                tab=0","                tab=if(previewDeferred)1 else 0")
            activity=activity.substring(0,from)+section+activity.substring(to)
        }
        updateResultBlock("    private fun decodeText(userText:String,password:ByteArray?=null) {",
            "    private fun decodeCloud(provider:String,reference:String) {","record","stored")
        updateResultBlock("    private fun decodeCloud(provider:String,reference:String) {",
            "    private fun decodeNurServers() {","record","stored")
        updateResultBlock("    private fun decodeNurServers() {",
            "    private fun clearVisibleResult() {","record","saved")
        // The new cloud-only provider decoder stores complete JSON but its preview
        // must use the same large-result guard as NUR, never render it eagerly.
        updateResultBlock("    private fun decodeServerVpnProvider(id:String) {",
            "    private fun importFiles(uris:List<Uri>,","record","saved")
        // Cloud MainActivity already classifies provider exceptions.
        // Batch files use the same safe preview rule for exceptionally large
        // outputs, but ordinary files retain their original navigation.
        val batchStart=activity.indexOf("    private fun importFiles(uris:List<Uri>,")
        require(batchStart>=0)
        val batchEnd=activity.indexOf("    private fun clearHistory()",batchStart)
        require(batchEnd>batchStart)
        var batch=activity.substring(batchStart,batchEnd)
        // QA-only failures report sanitized status codes locally to the tester.
        // Never display user payloads, full filenames, credentials or exceptions.
        // The base Activity already re-reads the verified local encrypted
        // formats before each import. Keep the Cloud-only opt-in refresh
        // behavior when a suffix is not recognized by that snapshot.
        batch=replaceOnce(batch,
            "                val verifiedImportFormats=if(BuildConfig.SPDECODE_CLOUD_ENABLED) {",
            """                var checkedUnknownSuffix=false
                var verifiedImportFormats=if(BuildConfig.SPDECODE_CLOUD_ENABLED) {""")
        batch=replaceOnce(batch,
            """                    val supported=ImportFormatRouter.detect(
                        routingName,BuildConfig.SPDECODE_CLOUD_ENABLED,
                        verifiedImportFormats
                    ) { AndroidDecoderCatalog.read(this@MainActivity) }
                        ?:throw DecodeFailure(R.string.unsupported)""",
            """                    var candidateFormat=ImportFormatRouter.detect(
                        routingName,BuildConfig.SPDECODE_CLOUD_ENABLED,
                        verifiedImportFormats
                    ) { AndroidDecoderCatalog.read(this@MainActivity) }
                    if(candidateFormat==null && BuildConfig.SPDECODE_CLOUD_ENABLED &&
                        !checkedUnknownSuffix && CloudCatalogUpdates.enabled(this@MainActivity)) {
                        checkedUnknownSuffix=true
                        try {
                            serverVpnApps=serverVpnCatalog.refreshIfDue(force=true)
                            verifiedImportFormats=serverVpnCatalog.cachedFormats()
                            fileFormats=verifiedImportFormats
                            candidateFormat=ImportFormatRouter.detect(
                                routingName,true,verifiedImportFormats
                            ) { AndroidDecoderCatalog.read(this@MainActivity) }
                        }catch(error:CancellationException){throw error}
                         catch(_:Exception){ /* Keep the last verified snapshot. */ }
                    }
                    val supported=candidateFormat?:throw DecodeFailure(R.string.unsupported)""")
        batch=replaceOnce(batch,
            "cloudClient.decodeFile(supported.suffix,input,password=secret,",
            """cloudClient.decodeFile(supported.suffix,input,password=secret,
                                    allowPasswordFromCatalog="password" in supported.credentialFields,""")
        batch=replaceOnce(batch,
            "cloudPassword?:hcPassword,hcHwid,",
            """cloudPassword?:hcPassword,hcHwid,
                                allowPasswordFromCatalog="password" in supported.credentialFields,""")
        batch=replaceOnce(batch,
            "CloudCredentialPolicy.fileNeedsPasswordDialog(supported.suffix) &&",
            """(CloudCredentialPolicy.fileNeedsPasswordDialog(supported.suffix) ||
                                (supported.suffix!="hc" &&
                                 "password" in supported.credentialFields)) &&""")
        batch=replaceOnce(batch,"                var failedProtectedHc=false",
            "                var failedProtectedHc=false\n" +
                "                val qaFailures=mutableListOf<String>()\n" +
                "                val cloudFailureMessages=mutableListOf<String>()")
        // MainActivity already passes (uri,cause) to the import callback.
        require(batch.contains("                    onFailure={uri,cause->")) {
            "Cloud batch diagnostic callback missing"
        }
        batch=replaceOnce(batch,
            "                        if(ImportFilenameNormalizer.forDetection(prepared?.filename?:filename)\n                            .endsWith(\".npvs\",ignoreCase=true) &&",
            """                        if(BuildConfig.SPDECODE_QA_BUILD) {
                            val ext=filename.substringAfterLast('.', "file").lowercase()
                                .filter { it.isLetterOrDigit() }.take(12).ifBlank { "file" }
                            val code=when(cause) {
                                is CloudDecodeClient.Failure ->
                                    cause.code + " (HTTP " + cause.httpStatus + ")"
                                is java.io.IOException -> {
                                    // Only fixed, locally generated codes, never
                                    // exception strings or sensitive file metadata.
                                    val label=cause.message.orEmpty()
                                    if(label.matches(Regex("CLOUD_[A-Z_]{3,65}"))) label
                                    else "CLIENT_IO_FAILURE"
                                }
                                is DecodeFailure -> "CLIENT_FORMAT_REJECTED"
                                is IllegalArgumentException -> "CLIENT_INVALID_ARGUMENT"
                                else -> "CLIENT_ERROR"
                            }
                            qaFailures.add(ext + ": " + code)
                        }
                        // Unsupported formats are expected compatibility
                        // outcomes, not additional generic errors.
                        if(!(cause is DecodeFailure && cause.stringId==R.string.unsupported) &&
                            (cause as? CloudDecodeClient.Failure)?.code!="UNSUPPORTED_FORMAT") {
                            cloudFailureMessages.add(
                                com.ghostdeveloper.spdecode.cloud.CloudUserErrors.message(
                                    this@MainActivity,cause))
                        }
                        if(ImportFilenameNormalizer.forDetection(prepared?.filename?:filename)
                            .endsWith(".npvs",ignoreCase=true) &&""")
        batch=replaceOnce(batch,"                    message=when {",
            """                    val qaDetails=if(BuildConfig.SPDECODE_QA_BUILD && qaFailures.isNotEmpty())
                        "\nQA: " + qaFailures.take(12).joinToString(" | ") else ""
                    message=when {""")
        // Restrict these summary changes to the batch section only.
        batch=batch.replace("+summary", "+summary+qaDetails")
        batch=replaceOnce(batch,"                        else->summary",
            "                        else->summary+qaDetails")
        batch=replaceOnce(batch,
            "                        else->summary+qaDetails\n                    }\n                    tab=0",
            """                        else->summary+qaDetails
                    }
                    if(!messageIsCredentialNotice && cloudFailureMessages.isNotEmpty()) {
                        message=message + "\n\n" +
                            cloudFailureMessages.distinct().take(3).joinToString("\n")
                    }
                    tab=0""")
        batch=replaceOnce(batch,"                    result=processed",
            "                    val previewDeferred=presentDecodedRecord(processed,saved)")
        batch=replaceOnce(batch,"historyPreferences.setSelectedId(processed.id)",
            "historyPreferences.setSelectedId(if(previewDeferred) null else processed.id)")
        batch=replaceOnce(batch,
            "                    tab=0\n                }\n                if(generation==importGeneration",
            "                    tab=if(previewDeferred)1 else 0\n                }\n                if(generation==importGeneration")
        activity=activity.substring(0,batchStart)+batch+activity.substring(batchEnd)

        // Compatible export changes only the generated Cloud menu; C0 source
        // hashes and the clipboard's three existing options stay intact.
        app = replaceOnce(app,
            """                            Triple(ResultExport.ORIGINAL,R.string.original_option,Icons.Outlined.Code)
                        ).forEach""",
            """                        ).let { options ->
                            if(copy || current.compatibleExport==null)
                                options + Triple(ResultExport.ORIGINAL,R.string.original_option,Icons.Outlined.Code)
                            else options
                        }.forEach""")
        app = replaceOnce(app,
            """                        }
                    }
                },
                confirmButton={TextButton(onClick={dialog=null}){""",
            """                        }
                        if(!copy) com.ghostdeveloper.spdecode.cloud.CompatibleExportButton(current,onDone={dialog=null})
                    }
                },
                confirmButton={TextButton(onClick={dialog=null}){""")

        // Refresh stays compact in APK; in Server VPN Cloud builds use the
        // authenticated catalog-refresh component only for the full-size control.
        app = replaceOnce(app,
            """                OutlinedButton(
                    onClick=onRefreshServerVpn,enabled=enableServerVpnRefresh,
                    modifier=Modifier.testTag("server_vpn_manual_refresh"),
                    contentPadding=PaddingValues(horizontal=12.dp,vertical=7.dp),
                ) {
                    if(refreshingServerVpn) CircularProgressIndicator(
                        modifier=Modifier.size(17.dp),strokeWidth=2.dp,color=White)
                    else Icon(Icons.Outlined.Refresh,null,tint=White,
                        modifier=Modifier.size(17.dp))
                    Spacer(Modifier.width(6.dp))
                    Text(stringResource(if(refreshingServerVpn) R.string.catalog_checking
                        else R.string.catalog_check_action),fontSize=12.sp,color=White)
                }
""",
            """                com.ghostdeveloper.spdecode.cloud.CatalogRefreshControl(
                    refreshingServerVpn,enableServerVpnRefresh,onRefreshServerVpn)
""")
        app = replaceOnce(app,
            "        if(catalogLoading) Row(verticalAlignment=Alignment.CenterVertically) {",
            """        if(BuildConfig.SPDECODE_CLOUD_ENABLED && cloudFormats.isEmpty() && catalogLoading) {
            com.ghostdeveloper.spdecode.cloud.CatalogEmptyLoading(catalogProgress,Modifier.weight(1f))
            return@Column
        }
        if(catalogLoading) Row(verticalAlignment=Alignment.CenterVertically) {""")
        app = replaceOnce(app,
            "            if(catalogLoading) {\n                Row(verticalAlignment=Alignment.CenterVertically) {",
            """            if(apps.isEmpty() && catalogLoading) {
                com.ghostdeveloper.spdecode.cloud.CatalogEmptyLoading(catalogProgress,Modifier.weight(1f))
                return@Column
            }
            if(catalogLoading) {
                Row(verticalAlignment=Alignment.CenterVertically) {""")
        activity = replaceOnce(activity,
            "        super.onResume()",
            """        super.onResume()
        com.ghostdeveloper.spdecode.cloud.CloudNotifications.ensureScheduled(this)
        com.ghostdeveloper.spdecode.cloud.CloudNotifications.enqueue(this)""")
        activity = replaceOnce(activity,
            "                            CloudLegalConsent.revoke(this@MainActivity)",
            """                            com.ghostdeveloper.spdecode.cloud.CloudNotifications.setEnabled(this@MainActivity,false)
                            CloudLegalConsent.revoke(this@MainActivity)""")
        activity = replaceOnce(activity,
            "serverVpnCatalog.refreshIfDue(force=force)",
            "serverVpnCatalog.refreshIfDue(force=force,onProgress={percent->scope.launch {catalogProgress=percent}})")


        // Cloud-only UI adaptation; the C0-locked original screens stay unchanged.
        app = replaceOnce(app,"onDecodeCloud:(String)->Unit={}",
            "onDecodeCloud:(String,String)->Unit={_,_->}")
        app = replaceOnce(app,
            "onDecodeCloud=onDecodeCloud,\n                        highlightGuide=",
            "onDecodeCloud=onDecodeCloud,cloudTextFormats=cloudTextFormats,\n                        highlightGuide=")
        app = replaceOnce(app,
            "    onDecodeCloud:(String)->Unit,\n    highlightGuide:Int?=null,",
            "    onDecodeCloud:(String,String)->Unit,\n    cloudTextFormats:List<CloudTextRoute>,\n    highlightGuide:Int?=null,")
        app = replaceOnce(app,
            "Text(stringResource(R.string.cloud_http_injector_open),",
            "Text(stringResource(R.string.cloud_global_title),")
        app = replaceOnce(app,
            """if(cloudExpanded) HttpInjectorCloudPanel(
            enabled=!busy,
            onDecode={input->
                awaitingCloudResult=true
                onDecodeCloud(input)
            },
        )""",
            """if(cloudExpanded) GlobalCloudImportPanel(
            enabled=!busy,
            routes=cloudTextFormats,
            onDecode={provider,input->
                awaitingCloudResult=true
                onDecodeCloud(provider,input)
            },
        )""")
        app = replaceOnce(app,
            "supportedFormats=cloudFormats,supportedTextFormats=cloudTextFormats,",
            "supportedFormats=cloudFormats,supportedTextFormats=cloudTextFormats.filterNot{it.kind==\"cloud\"&&it.suffix==\"hc\"},")

        // C0 remains immutable. Only the Play AAB receives the official
        // updater host and the suppression of Telegram's external APK prompt.
        if (enablePlayAab) {
            app=replaceOnce(app,
                "    onFeedbackSubmit:suspend (FeedbackDraft)->String={throw IllegalStateException(\"FEEDBACK_UNAVAILABLE\")},",
                "    onModalVisible:(Boolean)->Unit={},\n" +
                    "    onFeedbackSubmit:suspend (FeedbackDraft)->String={throw IllegalStateException(\"FEEDBACK_UNAVAILABLE\")},")
            app=replaceOnce(app,
                "    var dialog by remember{mutableStateOf<String?>(null)}",
                "    var dialog by remember{mutableStateOf<String?>(null)}\n" +
                    "    LaunchedEffect(dialog) { onModalVisible(dialog != null) }")
            activity=replaceOnce(activity,
                "    private var showLargeResultWarning by mutableStateOf(false)",
                "    private var showLargeResultWarning by mutableStateOf(false)\n" +
                    "    private var playUpdateVisible by mutableStateOf(false)\n" +
                    "    private var internalDialogVisible by mutableStateOf(false)")
            activity=replaceOnce(activity,
                "                onFeedbackSubmit={draft-> cloudClient.submitFeedback(draft)},",
                "                onFeedbackSubmit={draft-> cloudClient.submitFeedback(draft)},\n" +
                    "                onModalVisible={internalDialogVisible=it},")
            activity=replaceOnce(activity,
                "                availableAppUpdate=availableAppUpdate,",
                "                availableAppUpdate=null,")
            activity=replaceOnce(activity,
                "                whatsNew=showWhatsNew,",
                "                whatsNew=showWhatsNew && !playUpdateVisible,")
            activity=replaceOnce(activity,
                "                pendingServerVpnCatalogVersion=pendingServerVpnCatalogVersion,",
                "                pendingServerVpnCatalogVersion=if(playUpdateVisible) null else pendingServerVpnCatalogVersion,")
            activity=replaceOnce(activity,
                "            if(!busy) pendingCloudPasswordFile?.let { candidate ->",
                """            // The Play host does not exist in the Telegram APK.
            if (!showBrandedSplash) com.ghostdeveloper.spdecode.cloud.PlayInAppUpdateHost(
                allowPresentation=!busy && !showCloudLegal &&
                    (!showWhatsNew || playUpdateVisible) && message==null &&
                    (pendingServerVpnCatalogVersion==null || playUpdateVisible) &&
                    pendingCloudPasswordFile==null && pendingCloudPasswordText==null &&
                    pendingCredentialImport==null && guideStep==null &&
                    !internalDialogVisible &&
                    !com.ghostdeveloper.spdecode.cloud.NpvsRecipientPicker.isShowing &&
                    !com.ghostdeveloper.spdecode.cloud.HttpCustomCloudPrompt.isShowing,
                language=selectedLanguage,
                onExclusive={ active ->
                    playUpdateVisible=active
                    if(active) availableAppUpdate=null
                },
            )
            if(!busy) pendingCloudPasswordFile?.let { candidate ->""")
        }
        listOf(appPath to app, activityPath to activity).forEach { (name,content)->
            val output=cloudHistoryUiRoot.get().file(name).asFile
            output.parentFile.mkdirs()
            output.writeText(content,Charsets.UTF_8)
        }
    }
}

val prepareCloudOnlySources = tasks.register<Sync>("prepareCloudOnlySources") {
    from("src/main/java") {
        exclude("com/ghostdeveloper/spdecode/parity/**")
        exclude("com/ghostdeveloper/spdecode/TextProtocolDecoder.kt")
        exclude("com/ghostdeveloper/spdecode/TextPhaseGPort.kt")
        exclude("com/ghostdeveloper/spdecode/HttpInjectorCloudPort.kt")
        exclude("com/ghostdeveloper/spdecode/NurTunnelServerCatalog.kt")
        exclude("com/ghostdeveloper/spdecode/SpDecodeApp.kt")
        exclude("com/ghostdeveloper/spdecode/MainActivity.kt")
        exclude("com/ghostdeveloper/spdecode/FunctionalSettingsPanel.kt")
    }
    // This catalog is public display metadata, not a decryption engine.
    from("src/main/java/com/ghostdeveloper/spdecode/parity/AndroidDecoderCatalog.kt") {
        into("com/ghostdeveloper/spdecode/parity")
    }
    from("src/cloud/java")
    if (enablePlayAab) from("src/playUpdate/java")
    dependsOn(prepareCloudHistoryUiSource)
    from(cloudHistoryUiRoot)
    dependsOn(prepareQaSettingsSource)
    from(qaSettingsRoot)
    into(cloudSourceRoot)
}
val prepareCloudAssets = tasks.register<Sync>("prepareCloudAssets") {
    // No encrypted vault files, generated runtime vault key, network provider
    // endpoints, profile tables or other original decoder source materials.
    from("src/main/assets/decoder_catalog.json")
    if (enablePlayAab) from("src/playUpdate/assets/spdecode-play-updates-enabled.marker")
    // Google package-name ownership proof is a temporary CI-only APK. It is
    // NEVER included in ordinary Play AABs, external beta APKs or debug APKs.
    if (providers.environmentVariable("SPDECODE_ADI_VERIFICATION_BUILD").orNull == "true") {
        require(enableCloud) { "Package ownership proof requires a Cloud build" }
        val proof=file("src/main/assets/adi-registration.properties")
        require(proof.isFile && proof.length() in 16L..128L) {
            "Missing ephemeral Play Console package-ownership identifier"
        }
        from(proof)
    }
    into(cloudAssetRoot)
}

android {
    namespace = "com.ghostdeveloper.spdecode"
    // The app offers an independent in-app language picker. Google Play must
    // install every packaged locale from the AAB (including offline switches),
    // not deliver language configuration splits based on the device language.
    bundle {
        language {
            enableSplit = false
        }
    }
    if (enableCloud) {
        // Cloud source inputs are isolated from all 107 local engine classes.
        sourceSets.getByName("main").manifest.srcFile("src/cloud/AndroidManifest.xml")
        sourceSets.getByName("main").java.setSrcDirs(listOf(cloudSourceRoot))
        sourceSets.getByName("main").assets.setSrcDirs(listOf(cloudAssetRoot))
        // The Cloud binary deliberately excludes local decoder implementations.
        // Compile only Cloud instrumentation; historical offline suites use the
        // legacy test source set and would reference absent local engines.
        sourceSets.getByName("androidTest").java.setSrcDirs(
            listOf(file("src/cloudAndroidTest/java")))
    } else {
        // Non-distributed legacy baseline only, to protect historical CI.
        sourceSets.getByName("main").assets.setSrcDirs(listOf(vaultPackagedAssets))
        sourceSets.getByName("main").java.srcDir(vaultGeneratedKotlin)
    }
    compileSdk = 36
    ndkVersion = "27.2.12479018"
    defaultConfig {
        applicationId = "com.ghostdeveloper.spdecode"
        minSdk = 24
        targetSdk = 36
        versionCode = 42
        versionName = "1.1.27"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        // A public API origin is not a secret; all server secrets stay in the VPS.
        buildConfigField("boolean", "SPDECODE_CLOUD_ENABLED", enableCloud.toString())
        buildConfigField("boolean", "SPDECODE_QA_BUILD", enableQaBuild.toString())
        buildConfigField("boolean", "SPDECODE_PLAY_UPDATES", enablePlayAab.toString())
        // Public trust anchors; never package any recipient private key.
        // Public HPKE pin lives as masked bytes in native C++, not in BuildConfig.

        // Public Firebase application identifiers. Service-account keys stay exclusively on the VPS.
        mapOf("APP_ID" to "1:[0-9]+:android:[a-f0-9]+", "API_KEY" to "[A-Za-z0-9_-]{30,80}",
            "PROJECT_ID" to "[a-z][a-z0-9-]{4,60}", "SENDER_ID" to "[0-9]{5,30}").forEach { (key,pattern)->
            val value=providers.gradleProperty("noticeFirebase$key").orNull.orEmpty()
            require(value.isEmpty() || value.matches(Regex(pattern))) { "Invalid Firebase public identifier" }
            buildConfigField("String","NOTICE_FIREBASE_$key", "\"$value\"")
        }
        val noticeKeys=listOf("APP_ID","API_KEY","PROJECT_ID","SENDER_ID").map {
            providers.gradleProperty("noticeFirebase$it").orNull.orEmpty().isNotEmpty() }
        require(noticeKeys.all {it} || noticeKeys.none {it}) { "Firebase notice config must be complete" }
        manifestPlaceholders["spdecodeQaEnabled"] = enableQaBuild.toString()
        externalNativeBuild {
            cmake {
                arguments += "-DSPDECODE_CLOUD_ORIGIN=$cloudOrigin"
            }
        }
        resourceConfigurations += listOf("en", "es", "pt-rBR", "ar", "fa", "fr", "in", "ru", "de", "tr", "vi", "hi", "ja", "it")
    }
    buildFeatures { compose = true; buildConfig = true }
    externalNativeBuild {
        cmake {
            path = file("src/main/cpp/CMakeLists.txt")
            version = "3.22.1"
        }
    }
    packaging {
        resources {
            // Bouncy Castle and jspecify both ship JVM 9 multi-release metadata;
            // Android does not execute those JVM-specific OSGi descriptors.
            excludes += "META-INF/versions/**"
        }
    }
    // Production keystore passwords are injected only at build time by CI.
    // Never commit keystores, signing secrets or their obfuscated equivalents.
    signingConfigs {
        val path=providers.environmentVariable("SPDECODE_RELEASE_STORE_FILE").orNull
        val storePass=providers.environmentVariable("SPDECODE_RELEASE_STORE_PASSWORD").orNull
        val alias=providers.environmentVariable("SPDECODE_RELEASE_KEY_ALIAS").orNull
        val keyPass=providers.environmentVariable("SPDECODE_RELEASE_KEY_PASSWORD").orNull
        if(!path.isNullOrBlank() && !storePass.isNullOrBlank() &&
            !alias.isNullOrBlank() && !keyPass.isNullOrBlank()) {
            create("production") {
                storeFile=file(path)
                storePassword=storePass
                keyAlias=alias
                keyPassword=keyPass
                enableV1Signing=true
                enableV2Signing=true
                enableV3Signing=true
            }
        }
    }
    buildTypes {
        debug {
            buildConfigField("String", "TRUSTED_SIGNER_SHA256", "\"\"")
            buildConfigField("String", "PLAY_APP_SIGNER_SHA256", "\"\"")
        }
        release {
            // R8 shrinks/obfuscates release code only; debug retains readable
            // symbols for instrumentation and diagnostics.
            isMinifyEnabled = true
            isShrinkResources = true
            proguardFiles(getDefaultProguardFile("proguard-android-optimize.txt"),
                "proguard-rules.pro")
            // Fingerprint of the permanent certificate, injected by release CI.
            val trustedSha = providers.environmentVariable("SPDECODE_TRUSTED_SIGNER_SHA256").orNull
                .orEmpty().lowercase()
            require(trustedSha.isEmpty() || trustedSha.matches(Regex("[0-9a-f]{64}"))) {
                "Invalid trusted release signer fingerprint"
            }
            buildConfigField("String", "TRUSTED_SIGNER_SHA256", "\"$trustedSha\"")
            // Google Play may sign installs with a distinct app-signing certificate.
            val playSigner=providers.environmentVariable("SPDECODE_PLAY_APP_SIGNER_SHA256").orNull
                .orEmpty().lowercase()
            require(playSigner.isEmpty() || playSigner.matches(Regex("[0-9a-f]{64}"))) {
                "Invalid Play App Signing certificate SHA-256"
            }
            buildConfigField("String", "PLAY_APP_SIGNER_SHA256", "\"$playSigner\"")
            signingConfig=signingConfigs.findByName("production")
        }
    }
    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions { jvmTarget = "17" }
    testOptions { animationsDisabled = true }
}

dependencies {
    val composeBom = platform("androidx.compose:compose-bom:2025.04.01")
    implementation(composeBom)
    implementation("androidx.activity:activity-compose:1.10.1")
    // Release lint: ActivityResultContracts requires Fragment >=1.3.0.
    implementation("androidx.fragment:fragment:1.8.9")
    implementation("com.google.code.gson:gson:2.13.1")
    if (enableCloud) implementation("com.google.firebase:firebase-messaging:25.0.0")
    if (enablePlayAab) {
        implementation("com.google.android.play:app-update:2.1.0")
        implementation("androidx.lifecycle:lifecycle-runtime-compose:2.9.0")
    }
    // Classic Play Integrity nonce flow; the verdict is verified in C3 server-side.
    implementation("com.google.android.play:integrity:1.6.0")
    implementation("androidx.work:work-runtime-ktx:2.10.4")
    // Legacy decoders require BC; Cloud HPKE uses pinned native Mbed TLS.
    if (!enableCloud) implementation("org.bouncycastle:bcprov-jdk18on:1.86")
    implementation("androidx.activity:activity-ktx:1.10.1")
    implementation("androidx.lifecycle:lifecycle-viewmodel-ktx:2.9.0")
    implementation("androidx.datastore:datastore-preferences:1.1.7")
    implementation("androidx.core:core-splashscreen:1.0.1")
    implementation("androidx.room:room-runtime:2.7.2")
    implementation("androidx.room:room-ktx:2.7.2")
    kapt("androidx.room:room-compiler:2.7.2")
    implementation("androidx.compose.ui:ui")
    implementation("androidx.compose.foundation:foundation")
    implementation("androidx.compose.material3:material3")
    implementation("androidx.compose.material:material-icons-extended")
    implementation("androidx.compose.ui:ui-tooling-preview")
    debugImplementation("androidx.compose.ui:ui-tooling")

    androidTestImplementation(composeBom)
    androidTestImplementation("androidx.compose.ui:ui-test-junit4")
    debugImplementation("androidx.compose.ui:ui-test-manifest")
    androidTestImplementation("androidx.test.ext:junit:1.2.1")
    androidTestImplementation("androidx.test:runner:1.6.2")
}

// The generated Kotlin key and transformed assets must exist before each
// asset merge and Kotlin compilation, including unsigned CI and signed builds.
tasks.configureEach {
    if (name == "preBuild" ||
        (name.startsWith("merge") && name.endsWith("Assets")) ||
        (name.startsWith("compile") && name.endsWith("Kotlin")) ||
        name.startsWith("kaptGenerateStubs")) {
        if (enableCloud) {
            dependsOn(prepareCloudOnlySources)
            dependsOn(prepareCloudAssets)
        } else dependsOn(prepareSecureAssetVault)
    }
}

