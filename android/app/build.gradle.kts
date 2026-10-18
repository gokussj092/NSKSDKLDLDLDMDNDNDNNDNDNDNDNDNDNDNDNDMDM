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
val prepareCloudOnlySources = tasks.register<Sync>("prepareCloudOnlySources") {
    from("src/main/java") {
        exclude("com/ghostdeveloper/spdecode/parity/**")
        exclude("com/ghostdeveloper/spdecode/TextProtocolDecoder.kt")
        exclude("com/ghostdeveloper/spdecode/TextPhaseGPort.kt")
        exclude("com/ghostdeveloper/spdecode/HttpInjectorCloudPort.kt")
        exclude("com/ghostdeveloper/spdecode/NurTunnelServerCatalog.kt")
    }
    // This catalog is public display metadata, not a decryption engine.
    from("src/main/java/com/ghostdeveloper/spdecode/parity/AndroidDecoderCatalog.kt") {
        into("com/ghostdeveloper/spdecode/parity")
    }
    from("src/cloud/java")
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
