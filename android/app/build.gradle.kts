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
// C10 Firebase identifiers are public; sender credentials NEVER belong in Android.
val fcmProject=providers.environmentVariable("SPDECODE_FCM_PROJECT_ID").orNull.orEmpty()
val fcmAppId=providers.environmentVariable("SPDECODE_FCM_APP_ID").orNull.orEmpty()
val fcmKey=providers.environmentVariable("SPDECODE_FCM_API_KEY").orNull.orEmpty()
val fcmSender=providers.environmentVariable("SPDECODE_FCM_SENDER_ID").orNull.orEmpty()
val fcmFields=listOf(fcmProject,fcmAppId,fcmKey,fcmSender)
val fcmRequested=fcmFields.any(String::isNotEmpty)
if(fcmRequested)require(enableCloud && fcmFields.all(String::isNotEmpty) &&
    fcmProject.matches(Regex("[a-z][a-z0-9-]{5,62}")) &&
    fcmAppId.matches(Regex("[0-9]+:[0-9]+:android:[0-9a-fA-F]+")) &&
    fcmKey.matches(Regex("[A-Za-z0-9_-]{20,100}")) &&
    fcmSender.matches(Regex("[0-9]{5,20}"))) {
    "FCM public identifiers must be complete and valid for a Cloud build"
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
        val anchor = "        DeviceCredentialSettingsSection()"
        require(original.indexOf(anchor) >= 0 &&
            original.indexOf(anchor) == original.lastIndexOf(anchor)) {
            "QA Settings injection anchor absent or ambiguous; do not ship a build"
        }
        val source = original.replace(anchor,
            "        com.ghostdeveloper.spdecode.cloud.CloudQaSettingsCard()\n" + anchor)
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
                                onExport={onExportHistory(entry)},
                                onDelete={deletingAll=false;deletion=setOf(entry.id)},
                            )""")
        app = replaceOnce(app,
            "title={Text(stringResource(R.string.decode_notice_title))}",
            "title={Text(stringResource(R.string.cloud_failure_notice_title))}")
        var activity = originalRoot.file("MainActivity.kt").asFile.readText(Charsets.UTF_8)
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
            "    private fun decodeText(userText:String) {",
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

    private fun decodeText(userText:String) {""")
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
        updateResultBlock("    private fun decodeText(userText:String) {",
            "    private fun decodeCloud(reference:String) {","record","stored")
        updateResultBlock("    private fun decodeCloud(reference:String) {",
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
        batch=replaceOnce(batch,"                var failedProtectedHc=false",
            "                var failedProtectedHc=false\n" +
                "                val qaFailures=mutableListOf<String>()\n" +
                "                val cloudFailureMessages=mutableListOf<String>()")
        batch=replaceOnce(batch,"                    onFailure={uri,_-> ",
            "                    onFailure={uri,cause-> ")
        batch=replaceOnce(batch,
            "                        if(!BuildConfig.SPDECODE_CLOUD_ENABLED &&",
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
                        cloudFailureMessages.add(
                            com.ghostdeveloper.spdecode.cloud.CloudUserErrors.message(
                                this@MainActivity,cause))
                        if(!BuildConfig.SPDECODE_CLOUD_ENABLED &&""")
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
                    if(cloudFailureMessages.isNotEmpty()) {
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
        if (enableQaBuild) {
            exclude("com/ghostdeveloper/spdecode/FunctionalSettingsPanel.kt")
        }
    }
    // This catalog is public display metadata, not a decryption engine.
    from("src/main/java/com/ghostdeveloper/spdecode/parity/AndroidDecoderCatalog.kt") {
        into("com/ghostdeveloper/spdecode/parity")
    }
    from("src/cloud/java")
    dependsOn(prepareCloudHistoryUiSource)
    from(cloudHistoryUiRoot)
    if (enableQaBuild) {
        dependsOn(prepareQaSettingsSource)
        from(qaSettingsRoot)
    }
    into(cloudSourceRoot)
}
val prepareCloudAssets = tasks.register<Sync>("prepareCloudAssets") {
    // No encrypted vault files, generated runtime vault key, network provider
    // endpoints, profile tables or other original decoder source materials.
    from("src/main/assets/decoder_catalog.json")
    into(cloudAssetRoot)
}

android {
    namespace = "com.ghostdeveloper.spdecode"
    if (enableCloud) {
        // Cloud source inputs are isolated from all 107 local engine classes.
        sourceSets.getByName("main").java.setSrcDirs(listOf(cloudSourceRoot))
        sourceSets.getByName("main").assets.setSrcDirs(listOf(cloudAssetRoot))
    } else {
        // Non-distributed legacy baseline only, to protect historical CI.
        sourceSets.getByName("main").assets.setSrcDirs(listOf(vaultPackagedAssets))
        sourceSets.getByName("main").java.srcDir(vaultGeneratedKotlin)
    }
    compileSdk = 35
    ndkVersion = "27.2.12479018"
    defaultConfig {
        applicationId = "com.ghostdeveloper.spdecode"
        minSdk = 24
        targetSdk = 35
        versionCode = 25
        versionName = "1.1.4"
        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"
        // A public API origin is not a secret; all server secrets stay in the VPS.
        buildConfigField("boolean", "SPDECODE_CLOUD_ENABLED", enableCloud.toString())
        buildConfigField("boolean", "SPDECODE_QA_BUILD", enableQaBuild.toString())
        buildConfigField("boolean", "SPDECODE_FCM_CONFIGURED", fcmRequested.toString())
        buildConfigField("String", "SPDECODE_FCM_PROJECT_ID", "\"$fcmProject\"")
        buildConfigField("String", "SPDECODE_FCM_APP_ID", "\"$fcmAppId\"")
        buildConfigField("String", "SPDECODE_FCM_API_KEY", "\"$fcmKey\"")
        buildConfigField("String", "SPDECODE_FCM_SENDER_ID", "\"$fcmSender\"")
        manifestPlaceholders["spdecodeQaEnabled"] = enableQaBuild.toString()
        externalNativeBuild {
            cmake {
                arguments += "-DSPDECODE_CLOUD_ORIGIN=$cloudOrigin"
            }
        }
        resourceConfigurations += listOf("en", "es", "pt-rBR", "ar", "fa", "fr", "in", "ru", "de")
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
    // Classic Play Integrity nonce flow; the verdict is verified in C3 server-side.
    implementation("com.google.android.play:integrity:1.6.0")
    // FCM auto-registration remains disabled until a separate opt-in.
    implementation("com.google.firebase:firebase-messaging:24.1.1")
    implementation("androidx.work:work-runtime-ktx:2.10.4")
    // Lightweight Argon2id + XChaCha20-Poly1305 primitives for standard .ehi.
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
